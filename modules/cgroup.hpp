#pragma once

#include <cstdint>
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
    ModuleResult parse_config(const toml::table* config) final;

    struct CgroupRule {
        bool gress; //true-egress false-ingress
        uint32_t time_scale;
        uint64_t rate_bps;
        std::filesystem::path path;
    };

private:
    CgroupRule rule {};
    tc_process* skel {};
    uint32_t time_scale {};
};

}; // namespace module
