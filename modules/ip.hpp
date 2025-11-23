#pragma once

#include <chrono>
#include <modules/module.hpp>
#include <net/if.h>
#include <netinet/in.h>
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

[[maybe_unused]] static IpKey to_bpf_key(const IpRuleConfig& cfg) {
    IpKey key {};
    key.ip = ::htonl(cfg.ip);
    key.port = ::htons(cfg.port);
    key.proto = cfg.proto;
    key.dir = cfg.gress;
    return key;
}

// BPF MAP Value
struct IpValue {
    uint64_t rate_bps;
    uint64_t time_scale;
    uint64_t tokens;
    uint64_t last_ns;
    uint32_t lock; // bpf_spin_lock placeholder
};

[[maybe_unused]] static IpValue to_bpf_value(const IpRuleConfig& cfg) {
    IpValue val {};
    val.rate_bps = cfg.rate_bps;
    val.time_scale = cfg.time_scale;
    val.tokens = cfg.rate_bps;
    val.last_ns = 0;
    val.lock = 0;
    return val;
}

class IpModule final: public IModule {
public:
    IpModule() = default;
    ~IpModule() final = default;

    // IModule interface implementation
    Result load() final;
    void unload() final;
    std::string type() final;
    Result parse_config(const toml::table* table) final;
    FlowRate calc_rate() final;
    void init();

private:
    void init_buffers();

    std::vector<IpRuleConfig> configs;
    tc_ip* skel {};
    std::string iface_name = "lo";
    uint32_t ifindex = 0;
    bpf_tc_hook hook_ingress {};
    bpf_tc_hook hook_egress {};

    std::chrono::steady_clock::time_point last_time;
    FlowCounter last_flow {};
    std::vector<uint8_t> map_buffer;
    bool rate_initialized { false };
};

} // namespace module
