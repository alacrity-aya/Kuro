#pragma once

#include <cstdint>
#include <error/error.hpp>
#include <modules/module.hpp>
#include <optional>
#include <tc_process.skel.h>
#include <toml++/toml.hpp>

namespace module {

class CgroupModule final: public IModule {
public:
    struct CgroupRule {
        bool gress; //true-egress false-ingress
        uint32_t time_scale;
        uint64_t rate_bps;
        std::string path;
        std::string args;
    };

    ~CgroupModule() final = default;

    explicit CgroupModule() = default;
    ModuleResult load() final;
    void unload() final;
    std::string type() final;

    // config -> CgroupRule
    ModuleResult parse_config(const toml::table* config) final;

private:
    std::optional<CgroupRule> rule { std::nullopt };
    tc_process* skel {};
    std::optional<int> cgroup_fd = { std::nullopt };
    std::string uuid;

    ModuleResult attach_cgroup();
};

}; // namespace module
