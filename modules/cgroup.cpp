#include "utils.hpp"
#include <iostream>
#include <modules/cgroup.hpp>
#include <tc_process.skel.h>

namespace module {

ModuleResult CgroupModule::load() {
    skel = tc_process__open_and_load();
    if (skel == nullptr) {
        unload();
        return std::unexpected { ModuleError::OPEN_AND_LOAD_BPF_FAILED };
    }

    return {};
}

void CgroupModule::unload() {
    tc_process__destroy(skel);
}

std::string CgroupModule::type() {
    return "CgroupModule";
}

ModuleResult CgroupModule::parse_config(const toml::table* table) {
    TODO();
    std::cout << table << "\n";
    return {};
}

} // namespace module
