#include "config.h"
#include "error/error.hpp"
#include "modules/process_module.hpp"
#include "utils.hpp"
#include <expected>
#include <filesystem>
#include <iostream>
#include <print>

namespace {

volatile bool running = true;

void on_signal(int) {
    running = false;
}

} // namespace

// auto deleter = [](auto* ring_buf) { ring_buffer__free(ring_buf); };
// auto& manager = ModuleManager::instance();
// using process_module::ProcessModule;
// using process_module::ProcessRule;
int main() {
    toml::parse_result result = toml::parse_file(
        (std::filesystem::path(PROJECT_ROOT_DIR) / "config" / "config.toml").c_str()
    );
    if (!result) {
        std::cerr << "Parsing failed:\n" << result.error() << "\n";
        return 1;
    }
    const auto& config = result.table();
    const auto* processes = config["rule"]["process"].as_array();
    if (processes == nullptr) {
        utils::panic("process = nullptr");
    }

    for (const auto& process: *processes) {
        process_module::ProcessModule module { process.as_table() };

        if (auto result = module.load(); !result.has_value()) {
            std::println("Error: {}", module_error::error_to_string(result.error()));
            return -1;
        }

        std::cout << "module is running...\n";
        while (running) {
            if (auto result = module.poll_ring_buffer(100); !result.has_value()) {
                std::println("Error: {}", module_error::error_to_string(result.error()));
                break;
            }
        }

        module.unload();

        utils::todo("while(running)");
    }

    return 0;
}
