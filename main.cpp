#include <chrono>
#include <config.h>
#include <csignal>
#include <error/error.hpp>
#include <expected>
#include <filesystem>
#include <iostream>
#include <logger/logger.hpp>
#include <modules/cgroup.hpp>
#include <print>
#include <thread>
#include <utils/parser.hpp>
#include <utils/command.hpp>

namespace {

volatile bool running = true;

void on_signal(int) {
    std::println("\n====RECEIVE SIGNAL====");
    running = false;
}

} // namespace

int main() {
    if (auto r = utils::Command::exec("fastfetch"); !r.has_value())
        utils::panic("fastfecth failed");
    else
        std::println("{}", r.value());

    signal(SIGINT, on_signal);

    auto& logger = logger::Logger::instance();
    logger::StdoutAppender::ptr stdout_appender = std::make_shared<logger::StdoutAppender>();
    logger.set_priority(logger::LogPriority::TRACE)
        .add_appender(stdout_appender)
        .enable_time_recording()
        .set_mode(logger::LogMode::ASYNC);

    logger.trace("function main start");

    toml::parse_result result =
        toml::parse_file((std::filesystem::path(PROJECT_ROOT_DIR) / "config.toml").c_str());
    if (!result) {
        std::cerr << "Parsing failed:\n" << result.error() << "\n";
        return 1;
    }

    std::vector<module::CgroupModule> cgroup_modules {};
    const auto& config = result.table();
    const auto* cgroups = config["rule"]["cgroups"].as_array();

    for (const auto& cgroup: *cgroups) {
        cgroup_modules.emplace_back();
        auto& cgroup_module = cgroup_modules.back();

        auto ret = cgroup_module.parse_config(cgroup.as_table())
                       .and_then([&]() -> module::ModuleResult { return cgroup_module.load(); })
                       .or_else([&](const auto& err) -> module::ModuleResult {
                           cgroup_modules.pop_back();
                           logger.error("{}", err.to_string());
                           return std::unexpected { err };
                       });

        if (!ret)
            continue;
    }

    while (running) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        logger.trace("{:Mbps}", cgroup_modules[0].calc_rate());
    }

    for (auto& it: cgroup_modules) {
        it.unload();
    }

    logger.trace("function main end");

    return 0;
}
