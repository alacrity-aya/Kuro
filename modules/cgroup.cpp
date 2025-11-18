#include <cassert>
#include <error/error.hpp>
#include <expected>
#include <fcntl.h>
#include <modules/cgroup.hpp>
#include <optional>
#include <tc_process.skel.h>
#include <unistd.h>
#include <utils.hpp>

namespace module {

ModuleResult CgroupModule::load() {
    ModuleResult ret {};

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
            if (auto* map = this->skel->maps.cgroup_rules; map == nullptr)
                return std::unexpected { ModuleError { ErrorCode::FAILED_TO_FIND_MAP } };
            return {};
        })

        .and_then([this]() -> ModuleResult { return this->attach_cgroup(); })

        // TODO(alacrity): use sd-bus.h, not use utils::run_command
        .and_then([this]() -> ModuleResult {
            return utils::create_service(this->rule->path, this->rule->args, this->uuid);
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
    logger->info("{} is called", __PRETTY_FUNCTION__);
}

std::string CgroupModule::type() {
    return "CgroupModule";
}

ModuleResult CgroupModule::parse_config(
    const toml::table* config
) { // TODO(alacrity): bad implemetation, refactor it one day

    this->uuid = utils::uuid_v4();
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
            CgroupRule rule {};

            const auto* path_opt = config->get("path");
            CHECK_AND_BREAK(path_opt);
            rule.path = path_opt->value<std::string>().value();

            const auto* args_opt = config->get("args");
            CHECK_AND_BREAK(args_opt);
            rule.args = args_opt->value<std::string>().value();

            const auto* gress_opt = config->get("gress");
            CHECK_AND_BREAK(gress_opt);
            rule.gress = utils::parse_gress(gress_opt->value<std::string>().value()).value();

            const auto* rate_bps_opt = config->get("rate_bps");
            CHECK_AND_BREAK(rate_bps_opt);
            rule.rate_bps =
                utils::parse_rate_bps(rate_bps_opt->value<std::string>().value()).value();

            const auto* time_scale_opt = config->get("time_scale");
            CHECK_AND_BREAK(time_scale_opt);
            rule.time_scale =
                utils::parse_time_scale(time_scale_opt->value<std::string>().value()).value();

            logger->info(
                "path = {}, args = {}, gress = {}, rate_bps = {}, time_scale = {}",
                rule.path,
                rule.args,
                rule.gress,
                rule.rate_bps,
                rule.time_scale
            );

            this->rule = rule;

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

} // namespace module
