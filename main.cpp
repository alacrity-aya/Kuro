#include <config.h>
#include <csignal>
#include <error/error.hpp>
#include <expected>
#include <filesystem>
#include <iostream>
#include <logger/logger.hpp>
#include <memory>
#include <modules/cgroup.hpp>
#include <modules/ip.hpp>
#include <modules/module.hpp>
#include <print>
#include <utils/command.hpp>
#include <utils/parser.hpp>
#include <vector>

namespace {

volatile bool running = true;

void on_signal(int) {
    std::println("\n====RECEIVE SIGNAL====");
    running = false;
}

template<typename T>
void load_specific_modules(
    const toml::array* configs,
    std::vector<std::unique_ptr<module::IModule>>& modules,
    std::string_view type_name
) {
    auto& logger = logger::Logger::instance();
    if (configs) {
        for (const auto& config: *configs) {
            auto module_ptr = std::make_unique<T>();
            auto& current_module = *module_ptr;

            auto ret =
                current_module.parse_config(config.as_table())
                    .and_then([&]() -> module::Result { return current_module.load(); })
                    .or_else([&](const auto& err) -> module::Result {
                        logger.error("Failed to load {} module: {}", type_name, err.to_string());
                        return std::unexpected { err };
                    });

            if (ret) {
                modules.push_back(std::move(module_ptr));
            }
        }
    }
}

std::vector<std::unique_ptr<module::IModule>> load_modules(const toml::table& table) {
    std::vector<std::unique_ptr<module::IModule>> modules {};

    load_specific_modules<module::CgroupModule>(table["cgroups"].as_array(), modules, "Cgroup");

    load_specific_modules<module::IpModule>(table["ip"].as_array(), modules, "IP");

    return modules;
}

} // namespace

int main() {
    // init

    if (auto r = utils::Command::exec("fastfetch"); !r.has_value())
        utils::panic("fastfecth failed");
    else
        std::println("{}", r.value());

    signal(SIGINT, on_signal);

    logger::StdoutAppender::ptr stdout_appender = std::make_shared<logger::StdoutAppender>();
    logger::Logger::instance()
        .set_priority(logger::LogPriority::TRACE)
        .add_appender(stdout_appender)
        .enable_time_recording(false)
        .enable_thread_id(false)
        .set_mode(logger::LogMode::ASYNC);
    logger::trace("main starts ...");

    return 0;

    toml::parse_result result =
        toml::parse_file((std::filesystem::path(PROJECT_ROOT_DIR) / "rule.toml").c_str());
    if (!result) {
        std::cerr << "Parsing failed:\n" << result.error() << "\n";
        return 1;
    }

    // load module
    const auto& table = result.table();

    auto modules = load_modules(table);
    if (modules.empty()) {
        logger::warn("No modules were loaded successfully. Exiting.");
        return -1;
    }

    while (running) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        for (const auto& module_ptr: modules) {
            logger::info("Module {}: {:MB/s}", module_ptr->type(), module_ptr->calc_rate());
        }
    }

    for (auto& module: modules) {
        module->unload();
    }

    logger::trace("function main end");

    return 0;
}
