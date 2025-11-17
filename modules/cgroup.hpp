#pragma once

#include <error/error.hpp>
#include <filesystem>
#include <modules/module.hpp>
#include <tc_process.skel.h>
#include <toml++/toml.hpp>

namespace module {

class CgroupModule final: public IModule {
public:
    explicit CgroupModule() = default;
    ModuleResult load() final;
    void unload() final;
    std::string type() final;

    ~CgroupModule() final = default;

    // table -> CgroupRule
    ModuleResult parse_config(const toml::table* table) final;

    struct CgroupRule {
        bool engress;
        uint32_t time_scale;
        uint64_t rate_bps;
        std::filesystem::path path;
    };

private:
    tc_process* skel {};
    CgroupRule rule {};
};

}; // namespace module
