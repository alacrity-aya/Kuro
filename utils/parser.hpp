#pragma once

#include <arpa/inet.h>
#include <cpptrace/cpptrace.hpp>
#include <fcntl.h>
#include <format>
#include <iomanip>
#include <iostream>
#include <netinet/in.h>
#include <optional>
#include <print>
#include <random>
#include <regex>
#include <source_location>
#include <sstream>
#include <string>
#include <unistd.h>

namespace utils {

[[noreturn]] inline void
panic(std::string_view msg, const std::source_location& loc = std::source_location::current()) {
    std::println(
        "\033[31mPANIC at {}:{} in {}: {}\033[0m",
        loc.file_name(),
        loc.line(),
        loc.function_name(),
        msg
    );

    cpptrace::generate_trace().print();
    std::abort();
}

inline std::optional<uint64_t> parse_rate_bps(const std::string& rate_str) {
    std::regex pattern(R"((\d+)([KMG]?))");
    std::smatch match;
    if (std::regex_match(rate_str, match, pattern)) {
        uint64_t base = std::stoull(match[1].str());
        std::string unit = match[2].str();
        if (unit == "K")
            return base * 1024ULL;
        if (unit == "M")
            return base * 1024ULL * 1024;
        if (unit == "G")
            return base * 1024ULL * 1024 * 1024;
        return base;
    }
    return std::nullopt;
}

inline std::optional<uint64_t> parse_time_scale(const std::string& time_str) {
    static const std::regex pattern(R"(^([0-9]*\.?[0-9]+)(ns|us|ms|s|m)$)", std::regex::icase);

    std::smatch match;
    if (!std::regex_match(time_str, match, pattern))
        return std::nullopt;

    double value = std::stod(match[1].str());
    std::string unit = match[2].str();

    double ns = 0.0;

    if (unit == "ns") {
        ns = value;
    } else if (unit == "us") {
        ns = value * 1'000;
    } else if (unit == "ms") {
        ns = value * 1'000'000;
    } else if (unit == "s") {
        ns = value * 1'000'000'000;
    } else if (unit == "m") {
        ns = value * 60.0 * 1'000'000'000;
    } else {
        return std::nullopt;
    }

    if (ns < 0.0 || ns > static_cast<double>(std::numeric_limits<uint64_t>::max()))
        return std::nullopt;

    return static_cast<uint64_t>(std::llround(ns));
}

inline std::optional<uint8_t> parse_gress(const std::string& gress_str) {
    if (gress_str == "ingress")
        return 0;
    if (gress_str == "egress")
        return 1;
    return std::nullopt;
}

inline std::string ip_to_string(uint32_t ip_hbo) {
    in_addr addr;
    addr.s_addr = htonl(ip_hbo);
    std::array<char, INET_ADDRSTRLEN> buf {};
    inet_ntop(AF_INET, &addr, buf.data(), sizeof(buf));
    return std::string { buf.data() };
}

inline std::optional<uint32_t> parse_ip(const std::string& ip_str) {
    in_addr addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) != 1) {
        return std::nullopt;
    }
    return ntohl(addr.s_addr);
}

inline std::optional<std::string> protocol_to_string(uint8_t proto) {
    switch (proto) {
        case IPPROTO_TCP:
            return "TCP";
        case IPPROTO_UDP:
            return "UDP";
        default:
            return std::nullopt;
    }
}

// only support tcp and udp
inline std::optional<uint8_t> parse_protocol(const std::string& proto_str) {
    if (proto_str == "TCP" || proto_str == "tcp")
        return IPPROTO_TCP;
    if (proto_str == "UDP" || proto_str == "udp")
        return IPPROTO_UDP;

    return std::nullopt;
}

inline std::string format_elapsed_ns(uint64_t ns_since_boot) {
    uint64_t total_ms = ns_since_boot / 1'000'000ULL;
    uint64_t hours = total_ms / 3'600'000ULL;
    uint64_t minutes = (total_ms % 3'600'000ULL) / 60'000ULL;
    uint64_t seconds = (total_ms % 60'000ULL) / 1'000ULL;
    uint64_t millis = total_ms % 1'000ULL;

    std::ostringstream oss;
    oss << std::setfill('0') << std::setw(2) << hours << ':' << std::setw(2) << minutes << ':'
        << std::setw(2) << seconds << '.' << std::setw(3) << millis;
    return oss.str();
}

inline std::string uuid_v4() {
    static thread_local std::mt19937_64 rng(std::random_device {}());
    static thread_local std::uniform_int_distribution<uint64_t> dist;

    uint64_t part1 = dist(rng);
    uint64_t part2 = dist(rng);

    // UUID v4 standard：version=4, variant=10xxxxxx
    part2 = (part2 & 0x3FFFFFFFFFFFFFFF) | 0x8000000000000000; // variant
    part1 = (part1 & 0xFFFFFFFFFFFF0FFF) | 0x0000000000004000; // version 4

    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(8) << ((part1 >> 32) & 0xFFFFFFFF) << "-"
       << std::setw(4) << ((part1 >> 16) & 0xFFFF) << "-" << std::setw(4) << (part1 & 0xFFFF) << "-"
       << std::setw(4) << ((part2 >> 48) & 0xFFFF) << "-" << std::setw(12)
       << (part2 & 0xFFFFFFFFFFFF);

    return ss.str();
}

} // namespace utils
