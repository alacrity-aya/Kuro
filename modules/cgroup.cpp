#include <cassert>
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

        // TODO(alacrity): use sd-bus.h, not use utils::run_command
        .and_then([this]() -> ModuleResult {
            return utils::run_systemd(this->rule->path, this->rule->args);
        })

        .and_then([this]() -> ModuleResult { return this->attach_cgroup(); });
}

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
    //we should get the cgroup path via rule->path

    auto cgroup_path_opt = utils::get_cgroup_path(this->rule->path);
    this->cgroup_fd = open(cgroup_path_opt.value().c_str(), O_RDONLY);
    this->skel->links.drop_egress =
        bpf_program__attach_cgroup(this->skel->progs.drop_egress, cgroup_fd.value());

    return {};
}

} // namespace module
