#include "utils.hpp"
#include <cassert>
#include <expected>
#include <filesystem>
#include <modules/cgroup.hpp>
#include <optional>
#include <tc_process.skel.h>

namespace module {

using utils::todo;

ModuleResult CgroupModule::load() {
    if (this->skel = tc_process__open_and_load(); skel == nullptr) {
        return std::unexpected { ModuleError { ErrorCode::OPEN_AND_LOAD_BPF_FAILED } };
    }

    if (auto* map = skel->maps.cgroup_rules; map == nullptr) {
        return std::unexpected { ModuleError { ErrorCode::FAILED_TO_FIND_MAP } };
    }

    if (!this->rule.has_value()) {
        return std::unexpected { ModuleError { ErrorCode::EMPTY_RULE } };
    }

    //using systemd to create service here.
    todo();

    return {};
}

void CgroupModule::unload() {
    if (skel != nullptr) {
        tc_process__destroy(skel);
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

    while (true) {
        try {
            CgroupRule rule {};

            const auto* path_opt = config->get("path");
            if (path_opt == nullptr) {
                break;
            }
            rule.path = std::filesystem::path(path_opt->value<std::string>()->c_str());
            if (!std::filesystem::exists(rule.path)) {
                break;
            }

            const auto* gress_opt = config->get("gress");
            if (gress_opt == nullptr) {
                break;
            }
            rule.gress = utils::parse_gress(gress_opt->value<std::string>().value()).value();

            const auto* rate_bps_opt = config->get("rate_bps");
            if (rate_bps_opt == nullptr) {
                break;
            }
            rule.rate_bps =
                utils::parse_rate_bps(rate_bps_opt->value<std::string>().value()).value();

            const auto* time_scale_opt = config->get("time_scale");
            if (time_scale_opt == nullptr) {
                break;
            }
            rule.time_scale =
                utils::parse_time_scale(time_scale_opt->value<std::string>().value()).value();

            logger->info(
                "path = {}, gress = {}, rate_bps = {}, time_scale = {}",
                rule.path.c_str(),
                rule.gress,
                rule.rate_bps,
                rule.time_scale
            );

            this->rule = rule;

            return {};

        } catch (std::bad_optional_access& err) {
            logger->error("{}", err.what());
            return std::unexpected { ModuleError { ErrorCode::PARSING_CONFIG_FAILED } };
        }
    }
    logger->error("parse error");
    return std::unexpected { ModuleError { ErrorCode::PARSING_CONFIG_FAILED } };
}

} // namespace module
