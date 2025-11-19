#pragma once
#include "logger/logger.hpp"
#include <bpf/libbpf.h>
#include <cassert>
#include <error/error.hpp>
#include <format>
#include <toml++/toml.hpp>
namespace module {

struct FlowCounter {
    uint64_t accepted_bytes;
    uint64_t dropped_bytes;
    uint64_t accepted_packets;
    uint64_t dropped_packets;
};

struct FlowRate {
    double accepted_bytes_rate;
    double dropped_bytes_rate;
    double accepted_packets_rate;
    double dropped_packets_rate;
};

using error::ErrorCode;
using error::ModuleError;
using error::ModuleResult;
class IModule {
public:
    virtual ModuleResult load() = 0;
    virtual void unload() = 0;
    virtual std::string type() = 0;
    virtual ModuleResult parse_config(const toml::table* table) = 0;
    virtual ~IModule() = default;

    IModule() {
        logger = logger::Logger::get_instance();
        assert(logger.get());
    }

    virtual FlowRate calc_rate() = 0;

protected:
    std::shared_ptr<logger::Logger> logger;
    int cpus { libbpf_num_possible_cpus() };
};

} // namespace module

namespace std {

template<>
struct formatter<module::FlowRate, char> {
    static constexpr auto parse(format_parse_context& ctx) {
        return ctx.begin();
    }

    static auto format(const module::FlowRate& fr, format_context& ctx) {
        return format_to(
            ctx.out(),
            "FlowRate {{ .accepted_bytes_rate = {} .accepted_packets_rate = {} .dropped_bytes_rate = {} .dropped_packets_rate = {} }}",
            fr.accepted_bytes_rate,
            fr.accepted_packets_rate,
            fr.dropped_bytes_rate,
            fr.dropped_packets_rate
        );
    }
};

template<>
struct formatter<module::FlowCounter, char> {
    static constexpr auto parse(format_parse_context& ctx) {
        return ctx.begin();
    }

    static auto format(const module::FlowCounter& fc, format_context& ctx) {
        return format_to(
            ctx.out(),
            "FlowCounter {{ .accepted_bytes= {} .accepted_packets= {} .dropped_bytes= {} .dropped_packets= {} }}",
            fc.accepted_bytes,
            fc.accepted_packets,
            fc.dropped_bytes,
            fc.dropped_packets
        );
    }
};
} // namespace std
