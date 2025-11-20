#pragma once
#include "logger/logger.hpp"
#include <array>
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

    IModule(): logger { logger::Logger::instance() } {}

    virtual FlowRate calc_rate() = 0;

protected:
    logger::Logger& logger;
    int cpus { libbpf_num_possible_cpus() };
};

} // namespace module

namespace std {

template<>
struct formatter<module::FlowRate> {
    // Units supported for formatted output
    enum class Unit : uint8_t {
        RAW, // Default: Bytes/s (no suffix)

        // Bits-based units (value * 8)
        BPS, // bits/s
        KBPS, // kilobits/s
        MBPS, // megabits/s
        GBPS, // gigabits/s

        // Bytes-based units (value * 1)
        BPS_BYTE, // Bytes/s (explicit)
        KBPS_BYTE, // Kilobytes/s
        MBPS_BYTE, // Megabytes/s
        GBPS_BYTE // Gigabytes/s
    };

    Unit selected_unit = Unit::RAW;

    // Parse format specifier (e.g., "{:Mbps}" -> "Mbps")

    constexpr auto parse(std::format_parse_context& ctx) {
        const auto* it = ctx.begin();
        const auto* const end = ctx.end();

        if (it == end || *it == '}')
            return it;

        // Try to match each known token
        struct Entry {
            std::string_view token;
            Unit unit;
        };

        static constexpr std::array<Entry, 8> table = { {
            Entry { .token = "Bps", .unit = Unit::BPS },
            Entry { .token = "Kbps", .unit = Unit::KBPS },
            Entry { .token = "Mbps", .unit = Unit::MBPS },
            Entry { .token = "Gbps", .unit = Unit::GBPS },
            Entry { .token = "Bps_Byte", .unit = Unit::BPS_BYTE },
            Entry { .token = "KBps_Byte", .unit = Unit::KBPS_BYTE },
            Entry { .token = "MBps_Byte", .unit = Unit::MBPS_BYTE },
            Entry { .token = "GBps_Byte", .unit = Unit::GBPS_BYTE },
        } };

        for (const auto& [token, unit]: table) {
            const auto* temp = it;

            bool matched = true;
            for (char c: token) {
                if (temp == end || *temp != c) {
                    matched = false;
                    break;
                }
                ++temp;
            }

            // Must end before '}' or end
            if (matched && (temp == end || *temp == '}')) {
                it = temp;
                selected_unit = unit;
                return it;
            }
        }

        // Unknown specifier → ignore
        return it;
    }

    auto format(const module::FlowRate& fr, std::format_context& ctx) const {
        // Determine scaling factor
        double scale = 1.0;
        std::string_view unit_suffix;

        switch (selected_unit) {
            case Unit::RAW:
                scale = 1.0;
                break;

            // Bits = bytes * 8
            case Unit::BPS:
                scale = 8.0;
                unit_suffix = "bps";
                break;
            case Unit::KBPS:
                scale = 8.0 / 1024.0;
                unit_suffix = "Kbps";
                break;
            case Unit::MBPS:
                scale = 8.0 / (1024.0 * 1024.0);
                unit_suffix = "Mbps";
                break;
            case Unit::GBPS:
                scale = 8.0 / (1024.0 * 1024.0 * 1024.0);
                unit_suffix = "Gbps";
                break;

            // Bytes
            case Unit::BPS_BYTE:
                scale = 1.0;
                unit_suffix = "B/s";
                break;
            case Unit::KBPS_BYTE:
                scale = 1.0 / 1024.0;
                unit_suffix = "KB/s";
                break;
            case Unit::MBPS_BYTE:
                scale = 1.0 / (1024.0 * 1024.0);
                unit_suffix = "MB/s";
                break;
            case Unit::GBPS_BYTE:
                scale = 1.0 / (1024.0 * 1024.0 * 1024.0);
                unit_suffix = "GB/s";
                break;
        }

        // Apply unit scaling (only for byte-based rates)
        double acc_bytes = fr.accepted_bytes_rate * scale;
        double drop_bytes = fr.dropped_bytes_rate * scale;

        // Raw output (no unit transformation)
        if (selected_unit == Unit::RAW) {
            return std::format_to(
                ctx.out(),
                "FlowRate {{ .accepted_bytes_rate = {} .accepted_packets_rate = {} .dropped_bytes_rate = {} .dropped_packets_rate = {} }}",
                fr.accepted_bytes_rate,
                fr.accepted_packets_rate,
                fr.dropped_bytes_rate,
                fr.dropped_packets_rate
            );
        }

        // Formatted output with unit suffix
        return std::format_to(
            ctx.out(),
            "FlowRate {{ .accepted_bytes_rate = {:.2f} {} .accepted_packets_rate = {:.0f} pps .dropped_bytes_rate = {:.2f} {} .dropped_packets_rate = {:.0f} pps }}",
            acc_bytes,
            unit_suffix,
            fr.accepted_packets_rate,
            drop_bytes,
            unit_suffix,
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
