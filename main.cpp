// 1. toml

#include "error/error.hpp"
#include "utils.hpp"
#include <bpf/libbpf.h>
#include <expected>
#include <module.hpp>
#include <print>
#include <toml++/toml.hpp>

#include "modules/process_module.hpp"
#include <cstdint>
#include <iostream>

namespace {

using module_error::ModuleError;

volatile bool running = true;

void on_signal(int) {
    running = false;
}

std::expected<void, ModuleError> check() {
    auto project_root = utils::find_project_root();
    return {};
}

} // namespace

//     auto deleter = [](auto* ring_buf) { ring_buffer__free(ring_buf); };
//     auto& manager = ModuleManager::instance();
// using process_module::ProcessModule;
// using process_module::ProcessRule;
int main() {
    process_module::ProcessModule module;

    if (auto result = module.load(); !result.has_value()) {
        std::println("Error: {}", module_error::error_to_string(result.error()));
    }

    uint32_t pid;
    std::cin >> pid;
    process_module::ProcessRule rule {
        .target_pid = pid,
        .rate_bps = 1024ULL * 1024 * 10,
        .gress = 1,
        .time_scale = 10,
    };
    if (!module.update_rule(rule).has_value()) {
        std::println(stderr, "update_rule failed!");
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

    return 0;

    // TODO(alacrity): toml -> ProcessRule
}
