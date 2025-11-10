#include "error/error.hpp"
#include "utils.hpp"
#include <bpf/libbpf.h>
#include <expected>
#include <module.hpp>
#include <print>

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

#include "modules/process_module.hpp"
#include <cstdint>
#include <iostream>

using process_module::ProcessModule;
using process_module::ProcessRule;
int main() {
    if (getuid() != 0) {
        std::println(stderr, "Root privileges are required");
        return -1;
    }
    auto project_root = utils::find_project_root();
    if (!project_root.has_value()) {
        std::println(stderr, "Failed to find project root");
        return -1;
    }
    //     auto deleter = [](auto* ring_buf) { ring_buffer__free(ring_buf); };
    //     auto& manager = ModuleManager::instance();
    ProcessModule module;

    if (!module.load(project_root.value())) {
        std::cerr << "failed to load module\n";
        return 1;
    }

    uint32_t pid;
    std::cin >> pid;
    ProcessRule rule {
        .target_pid = pid,
        .rate_bps = 1024ULL * 1024 * 10,
        .gress = 1,
        .time_scale = 10,
    };
    if (!module.update_rule(rule).has_value()) {
        std::println(stderr, "update_rule failed!");
        return -1;
    }

    std::cout << "模块运行中...\n";
    while (running) {
        ring_buffer__poll(module.rb_, 100);
    }

    // 析构时自动清理
    return 0;
}
