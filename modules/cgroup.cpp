#include <bpf/libbpf.h>
#include <cassert>
#include <chrono>
#include <error/error.hpp>
#include <expected>
#include <fcntl.h>
#include <modules/cgroup.hpp>
#include <optional>
#include <tc_process.skel.h>
#include <unistd.h>
#include <utils.hpp>
#include <vector>

namespace module {

ModuleResult CgroupModule::load() {
    ModuleResult ret {};
    this->init();

    return ret

        .and_then([this]() -> ModuleResult {
            if (!this->rule.has_value())
                return std::unexpected { ModuleError { ErrorCode::EMPTY_RULE } };
            return {};
        })

        .and_then([this]() -> ModuleResult {
            if (this->skel = tc_process__open_and_load(); this->skel == nullptr)
                return std::unexpected { ModuleError { ErrorCode::OPEN_AND_LOAD_BPF_FAILED } };
            return {};
        })

        .and_then([this]() -> ModuleResult {
            auto* map = this->skel->maps.cgroup_rules;
            if (map == nullptr)
                return std::unexpected { ModuleError { ErrorCode::FAILED_TO_FIND_MAP } };

            uint32_t map_key = 0;

            if (bpf_map__update_elem(
                    map,
                    &map_key,
                    sizeof(map_key),
                    &this->rule.value().rule,
                    sizeof(this->rule.value().rule),
                    0 //WARNING: should this to be zero?
                )
                != 0)
            {
                return std::unexpected { ModuleError { ErrorCode::FAILED_TO_UPDATE_MAP } };
            }
            return {};
        })

        // TODO(alacrity): use sd-bus.h, not use utils::run_command
        .and_then([this]() -> ModuleResult {
            return utils::service_start(this->rule->path, this->rule->args, this->uuid);
        })

        .and_then([this]() -> ModuleResult {
            utils::service_status(this->uuid);
            return this->attach_cgroup();
        })
        .or_else([this](const auto&& err) -> ModuleResult {
            this->unload();
            return std::unexpected { err };
        });
}

// TODO(alacrity): using RAII to load and unload
void CgroupModule::unload() {
    if (this->skel != nullptr) {
        tc_process__destroy(this->skel);
    }
    if (this->cgroup_fd != std::nullopt) {
        close(this->cgroup_fd.value());
    }
    utils::service_stop(this->uuid);

    logger->info("{} is called", __PRETTY_FUNCTION__);
}

void CgroupModule::init() {
    constexpr uint64_t elem_sz = ((sizeof(FlowCounter) + 7) & ~7);
    this->raw.resize(elem_sz * this->cpus);
    this->uuid = utils::uuid_v4();
}

std::string CgroupModule::type() {
    return "CgroupModule";
}

ModuleResult CgroupModule::parse_config(
    const toml::table* config
) { // TODO(alacrity): bad implemetation, refactor it one day

    if (config == nullptr) {
        logger->error("config = nullptr");
        return std::unexpected { ModuleError { ErrorCode::EMPTY_CONFIG_NODE } };
    }

    std::source_location loc;

    do {
        try {
#define CHECK_AND_BREAK(variable) \
    if ((variable) == nullptr) { \
        loc = std::source_location::current(); \
        break; \
    }
            ConfigCgroupRule config_rule {};

            const auto* path_opt = config->get("path");
            CHECK_AND_BREAK(path_opt);
            config_rule.path = path_opt->value<std::string>().value();

            const auto* args_opt = config->get("args");
            CHECK_AND_BREAK(args_opt); // TODO(alacrity): args can be nullable
            config_rule.args = args_opt->value<std::string>().value();

            const auto* gress_opt = config->get("gress");
            CHECK_AND_BREAK(gress_opt);
            config_rule.rule.gress =
                utils::parse_gress(gress_opt->value<std::string>().value()).value();

            const auto* rate_bps_opt = config->get("rate_bps");
            CHECK_AND_BREAK(rate_bps_opt);
            config_rule.rule.rate_bps =
                utils::parse_rate_bps(rate_bps_opt->value<std::string>().value()).value();

            const auto* time_scale_opt = config->get("time_scale");
            CHECK_AND_BREAK(time_scale_opt);
            config_rule.rule.time_scale =
                utils::parse_time_scale(time_scale_opt->value<std::string>().value()).value();

            logger->info(
                "path = {}, args = {}, gress = {}, rate_bps = {}, time_scale = {}",
                config_rule.path,
                config_rule.args,
                config_rule.rule.gress,
                config_rule.rule.rate_bps,
                config_rule.rule.time_scale
            );

            this->rule = config_rule;

#undef CHECK_AND_BREAK

            return {}; // parsing successed

        } catch (std::bad_optional_access& err) {
            return std::unexpected {
                ModuleError { ErrorCode::PARSING_CONFIG_FAILED, err.what(), loc }
            };
        }
    } while (false);

    return std::unexpected { ModuleError { ErrorCode::PARSING_CONFIG_FAILED, "parse error", loc } };
}

ModuleResult CgroupModule::attach_cgroup() {
    // TODO(alacrity): remember to attach ingress
    if (this->cgroup_fd = utils::get_cgroup_fd(this->uuid); !this->cgroup_fd.has_value()) {
        return std::unexpected { ModuleError { ErrorCode::FAILED_TO_GET_CGROUP_FD } };
    }
    logger->trace("get cgroup fd {}", this->cgroup_fd.value());

    if (auto* ret = this->skel->links.drop_egress =
            bpf_program__attach_cgroup(this->skel->progs.drop_egress, cgroup_fd.value());
        ret == nullptr)
    {
        return std::unexpected { ModuleError { ErrorCode::ATTACH_BPF_FAILED } };
    }

    return {};
}

FlowRate CgroupModule::calc_rate() {
    constexpr uint64_t elem_sz = ((sizeof(FlowCounter) + 7) & ~7);
    const uint32_t key = 0;

    if (bpf_map__lookup_elem(
            this->skel->maps.flow_stats,
            &key,
            sizeof(key),
            this->raw.data(),
            this->raw.size(),
            0
        )
        != 0)
    {
        logger->warn("{}: failed to lookup bpf map", std::source_location::current());
        return FlowRate {};
    }

    FlowCounter total {};

    for (int cpu = 0; cpu < this->cpus; cpu++) {
        const auto* pcpu = reinterpret_cast<const FlowCounter*>(this->raw.data() + (cpu * elem_sz));
        total.accepted_bytes += pcpu->accepted_bytes;
        total.dropped_bytes += pcpu->dropped_bytes;
        total.accepted_packets += pcpu->accepted_packets;
        total.dropped_packets += pcpu->dropped_packets;
    }
    auto now = std::chrono::steady_clock::now();

    // first call: no rate
    if (!this->rate_initialized) [[unlikely]] {
        this->rate_initialized = true;
        this->last_time = now;
        this->last_flow = total;
        return FlowRate {};
    }

    const double dt = std::chrono::duration<double>(now - last_time).count();
    const double safe_dt = (dt > 1e-9) ? dt : 1e-9;

    uint64_t delta_acc_bytes = total.accepted_bytes - last_flow.accepted_bytes;
    uint64_t delta_drop_bytes = total.dropped_bytes - last_flow.dropped_bytes;
    uint64_t delta_acc_pkts = total.accepted_packets - last_flow.accepted_packets;
    uint64_t delta_drop_pkts = total.dropped_packets - last_flow.dropped_packets;

    logger->info(
        "{} {} {} {} {}",
        delta_acc_bytes,
        delta_drop_bytes,
        delta_acc_pkts,
        delta_drop_pkts,
        safe_dt
    );

    this->last_flow = total;
    this->last_time = now;

    return FlowRate {
        .accepted_bytes_rate = static_cast<double>(delta_acc_bytes) / safe_dt,
        .dropped_bytes_rate = static_cast<double>(delta_drop_bytes) / safe_dt,
        .accepted_packets_rate = static_cast<double>(delta_acc_pkts) / safe_dt,
        .dropped_packets_rate = static_cast<double>(delta_drop_pkts) / safe_dt,
    };
}
} // namespace module
