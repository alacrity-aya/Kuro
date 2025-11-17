#include "config.h"
#include "modules/cgroup.hpp"
#include <filesystem>
#include <iostream>
#include <print>

namespace {

// volatile bool running = true;

// void on_signal(int) [[maybe_unused]] {
//     running = false;
// }

} // namespace

// auto deleter = [](auto* ring_buf) { ring_buffer__free(ring_buf); };
// auto& manager = ModuleManager::instance();
int main() {
    toml::parse_result result =
        toml::parse_file((std::filesystem::path(PROJECT_ROOT_DIR) / "config.toml").c_str());
    if (!result) {
        std::cerr << "Parsing failed:\n" << result.error() << "\n";
        return 1;
    }

    const auto& config = result.table();
    const auto* cgroups = config["rule"]["cgroups"].as_array();

    std::println("before entering loop");
    for (const auto& cgroup: *cgroups) {
        std::println("enter loop");
        auto cgroup_module = module::CgroupModule {};
        cgroup_module.parse_config(cgroup.as_table());
    }

    return 0;
}
