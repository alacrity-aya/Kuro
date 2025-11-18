#include <config.h>
#include <error/error.hpp>
#include <filesystem>
#include <iostream>
#include <modules/cgroup.hpp>

#include <logger/logger.hpp>

namespace {

volatile bool running = true;

[[maybe_unused]] void on_signal(int) {
    running = false;
}

} // namespace

int main() {
    auto logger = logger::Logger::get_instance();
    logger::StdoutAppender::ptr stdout_appender = std::make_shared<logger::StdoutAppender>();
    logger->set_priority(logger::LogPriority::TRACE).add_appender(stdout_appender);

    logger->trace("function main start");

    toml::parse_result result =
        toml::parse_file((std::filesystem::path(PROJECT_ROOT_DIR) / "config.toml").c_str());
    if (!result) {
        std::cerr << "Parsing failed:\n" << result.error() << "\n";
        return 1;
    }

    const auto& config = result.table();
    const auto* cgroups = config["rule"]["cgroups"].as_array();

    for (const auto& cgroup: *cgroups) {
        auto cgroup_module = module::CgroupModule {};
        if (auto ret = cgroup_module.parse_config(cgroup.as_table()); !ret.has_value()) {
            logger->error("{}", ret.error().to_string() + " skipping loading this module");
            continue;
        }
        if (auto ret = cgroup_module.load(); !ret.has_value()) {
            logger->error("{}", ret.error().to_string());
            cgroup_module.unload();
        }
    }
    logger->trace("function main end");

    return 0;
}
