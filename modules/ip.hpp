#pragma once

#include <chrono>
#include <modules/module.hpp>
#include <net/if.h>
#include <tc_ip.skel.h>
#include <vector>

namespace module {

struct IpRuleConfig {
    uint32_t ip; // Network Byte Order
    uint16_t port; // Network Byte Order
    uint8_t proto; // IPPROTO_TCP / UDP
    uint8_t gress; // 0=Ingress, 1=Egress
    uint64_t rate_bps;
    uint32_t time_scale;
};

// BPF MAP Key (must be indentical with struct in tc_ip.c)
struct IpKey {
    uint32_t ip;
    uint16_t port;
    uint8_t proto;
    uint8_t dir;
};

// BPF MAP Value
struct IpValue {
    uint64_t rate_bps;
    uint64_t time_scale;
    uint64_t tokens;
    uint64_t last_ns;
    uint32_t lock; // bpf_spin_lock placeholder
};

class IpModule final: public IModule {
public:
    IpModule() = default;
    ~IpModule() final = default;

    // IModule interface implementation
    ModuleResult load() final;
    void unload() final;
    std::string type() final;
    ModuleResult parse_config(const toml::table* table) final;
    FlowRate calc_rate() final;

private:
    void init_buffers();

    struct tc_ip* skel = nullptr;
    std::vector<IpRuleConfig> configs;
    std::string interface_name = "lo";
    int if_index = 0;

    struct bpf_tc_hook hook_ingress {};
    struct bpf_tc_hook hook_egress {};
    bool ingress_attached = false;
    bool egress_attached = false;

    std::vector<char> raw_stats_buffer; // for reading percpu map
    bool rate_initialized = false;
    FlowCounter last_flow {};
    std::chrono::steady_clock::time_point last_time;
};

} // namespace module
