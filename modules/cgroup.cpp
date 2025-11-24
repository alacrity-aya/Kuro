#include <bpf/libbpf.h>
#include <cassert>
#include <chrono>
#include <error/error.hpp>
#include <expected>
#include <fcntl.h>
#include <filesystem>
#include <format>
#include <modules/cgroup.hpp>
#include <optional>
#include <tc_cgroup.skel.h>
#include <unistd.h>
#include <utils/parser.hpp>
#include <utils/systemd.hpp>
#include <vector>

namespace module {

Result CgroupModule::load() {
    Result ret {};
    this->init();

    return ret
        .and_then([this]() -> Result {
            if (!this->rule.has_value())
                return std::unexpected { Error { ErrorCode::EMPTY_RULE } };
            return {};
        })

        .and_then([this]() -> Result {
            if (this->skel = tc_cgroup__open_and_load(); this->skel == nullptr)
                return std::unexpected { Error { ErrorCode::OPEN_AND_LOAD_BPF_FAILED } };
            return {};
        })

        .and_then([this]() -> Result {
            auto* map = this->skel->maps.cgroup_rules;
            if (map == nullptr)
                return std::unexpected { Error { ErrorCode::FAILED_TO_FIND_MAP } };

            uint32_t map_key = 0;

            if (bpf_map__update_elem(
                    map,
                    &map_key,
                    sizeof(map_key),
                    &this->rule.value().rule,
                    sizeof(this->rule.value().rule),
                    0
                )
                != 0)
            {
                return std::unexpected { Error { ErrorCode::FAILED_TO_UPDATE_MAP } };
            }
            return {};
        })

        // TODO(alacrity): use sd-bus.h, not use utils::run_command
        .and_then([this]() -> Result {
            return service_start(
                utils::ServiceStartOptions { .executable_path = this->rule->path,
                                             .args = this->rule->args,
                                             .service_id = this->uuid }
            );
        })

        .and_then([this]() -> Result {
            utils::service_status(this->uuid);
            return this->attach_cgroup();
        })
        .or_else([this](const auto&& err) -> Result {
            this->unload();
            return std::unexpected { err };
        });
}

// TODO(alacrity): using RAII to load and unload
void CgroupModule::unload() {
    if (this->skel != nullptr) {
        tc_cgroup__destroy(this->skel);
    }
    if (this->cgroup_fd != std::nullopt) {
        close(this->cgroup_fd.value());
    }
    utils::service_stop(this->uuid);

    logger.info("{} is called", __PRETTY_FUNCTION__);
}

void CgroupModule::init() {
    constexpr uint64_t elem_sz = ((sizeof(FlowCounter) + 7) & ~7);
    this->raw.resize(elem_sz * this->cpus);
    this->uuid = utils::uuid_v4();
}

std::string CgroupModule::type() {
    return "CgroupModule";
}

Result CgroupModule::parse_config(const toml::table* config) {
    if (config == nullptr) {
        logger.error("config == nullptr");
        return std::unexpected { Error { ErrorCode::EMPTY_CONFIG_NODE } };
    }

    logger.debug("config is not null");

    ConfigCgroupRule config_rule {};

    auto config_error = [&](const std::string& msg,
                            std::source_location loc = std::source_location::current()) {
        logger.error("Configuration error: {}", msg);
        return std::unexpected { Error { ErrorCode::PARSING_CONFIG_FAILED, msg, loc } };
    };

    // 2.1 Path - Required
    const auto* path_node = config->get("path");
    if (path_node == nullptr) {
        return std::unexpected { Error { ErrorCode::PARSE_MISSING_REQUIRED_FIELD, ": path" } };
    }
    config_rule.path = path_node->value<std::string>().value_or("");
    if (config_rule.path.empty()) {
        return config_error("Key 'path' is missing, empty, or not a string.");
    }
    if (!std::filesystem::exists(config_rule.path)) {
        return std::unexpected {
            Error {
                ErrorCode::PARSING_CONFIG_FAILED,
                std::format("path: {} not exists", config_rule.path),
            },
        };
    }

    // 2.2 Arguments (args) - Optional
    if (const auto* args_node = config->get("args"); args_node != nullptr) {
        config_rule.args = args_node->value<std::string>().value_or("");
    }

    // 2.3 Direction (gress) - Required
    const auto* gress_node = config->get("gress");
    if (gress_node == nullptr) {
        return std::unexpected { Error { ErrorCode::PARSE_MISSING_REQUIRED_FIELD, ": gress" } };
    }
    auto gress_str_opt = gress_node->value<std::string>();
    if (!gress_str_opt) {
        // Logic: key exists but isn't a string?
        return config_error("Key 'gress' exists but is not a string.");
    }

    // Updated: Handle std::expected
    auto gress_res = utils::parse_gress(gress_str_opt.value());
    if (!gress_res) {
        return std::unexpected { Error {
            gress_res.error(),
            std::format("'gress_str = {}'", gress_str_opt.value()),
        } };
    }
    config_rule.rule.gress = gress_res.value();

    // 2.4 Rate (rate_bps) - Required
    const auto* rate_bps_node = config->get("rate_bps");
    if (rate_bps_node == nullptr) {
        return std::unexpected { Error { ErrorCode::PARSE_MISSING_REQUIRED_FIELD, ": rate_bps" } };
    }
    auto rate_bps_str_opt = rate_bps_node->value<std::string>();
    if (!rate_bps_str_opt) {
        return config_error("Key 'rate_bps' exists but is not a string.");
    }

    // Updated: Handle std::expected
    auto rate_bps_res = utils::parse_rate_bytes_ps(rate_bps_str_opt.value());
    if (!rate_bps_res) {
        return std::unexpected { Error {
            rate_bps_res.error(),
            std::format("'rate_bps_str = {}'", rate_bps_str_opt.value()),
        } };
    }
    config_rule.rule.rate_bps = rate_bps_res.value();

    // 2.5 Time Scale (time_scale) - Optional
    const auto* time_scale_node = config->get("time_scale");
    if (time_scale_node != nullptr) {
        auto time_scale_str_opt = time_scale_node->value<std::string>();
        if (!time_scale_str_opt) {
            return config_error("Key 'time_scale' exists but is not a string.");
        }

        // Updated: Handle std::expected
        auto time_scale_res = utils::parse_time_scale(time_scale_str_opt.value());
        if (!time_scale_res) {
            return std::unexpected { Error {
                time_scale_res.error(),
                std::format("'time_scale_str = {}'", time_scale_str_opt.value()),
            } };
        }
        config_rule.rule.time_scale = time_scale_res.value();
    } else {
        config_rule.rule.time_scale = 0;
    }

    logger.info(
        "parsing configuration successfully: path = {}, args = {}, gress = {}, rate_bps = {}, time_scale = {}",
        config_rule.path,
        config_rule.args,
        config_rule.rule.gress,
        config_rule.rule.rate_bps,
        config_rule.rule.time_scale
    );

    this->rule = config_rule;

    return {};
}

Result CgroupModule::attach_cgroup() {
    if (this->cgroup_fd = utils::get_cgroup_fd(this->uuid); !this->cgroup_fd.has_value()) {
        return std::unexpected { Error { ErrorCode::FAILED_TO_GET_CGROUP_FD } };
    }
    logger.info("get cgroup fd {}", this->cgroup_fd.value());

    if (auto* ret = this->skel->links.limit_egress_traffic =
            bpf_program__attach_cgroup(this->skel->progs.limit_egress_traffic, cgroup_fd.value());
        ret == nullptr)
    {
        return std::unexpected { Error { ErrorCode::ATTACH_BPF_FAILED } };
    }

    if (auto* ret = this->skel->links.limit_ingress_traffic =
            bpf_program__attach_cgroup(this->skel->progs.limit_ingress_traffic, cgroup_fd.value());
        ret == nullptr)
    {
        return std::unexpected { Error { ErrorCode::ATTACH_BPF_FAILED } };
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
        logger.warn("{}: failed to lookup bpf map", std::source_location::current());
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
