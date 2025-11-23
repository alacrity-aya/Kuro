#pragma once

#include <cstdint>
#include <error/error.hpp>
#include <modules/module.hpp>
#include <optional>
#include <tc_cgroup.skel.h>
#include <toml++/toml.hpp>

namespace module {

class CgroupModule final: public IModule {
public:
    struct CgroupRule {
        uint8_t gress; // 1-egress 0-ingress
        uint64_t time_scale;
        uint64_t rate_bps;
    };

    struct ConfigCgroupRule {
        CgroupRule rule;
        std::string path;
        std::string args;
    };

    ~CgroupModule() final = default;

    explicit CgroupModule() = default;
    Result load() final;
    void unload() final;
    std::string type() final;

    // config -> CgroupRule
    Result parse_config(const toml::table* config) final;

    FlowRate calc_rate() final;

private:
    std::optional<ConfigCgroupRule> rule { std::nullopt };
    tc_cgroup* skel {};
    std::optional<int> cgroup_fd = { std::nullopt };
    std::string uuid;
    std::vector<uint8_t> raw;
    bool rate_initialized { false };

    std::chrono::steady_clock::time_point last_time;
    FlowCounter last_flow {};

    Result attach_cgroup();
    void init();
};

}; // namespace module
