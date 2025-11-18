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

    // config -> CgroupRule
    ModuleResult parse_config(const toml::table* config) final;

    struct CgroupRule {
        bool gress; //true-egress false-ingress
        uint32_t time_scale;
        uint64_t rate_bps;
        std::string cmd;
    };

private:
    std::optional<CgroupRule> rule { std::nullopt };
    tc_process* skel {};
};

}; // namespace module
