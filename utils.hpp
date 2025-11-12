#pragma once

#include <arpa/inet.h>
#include <array>
#include <cstdlib>
#include <execinfo.h>
#include <format>
#include <iomanip>
#include <netinet/in.h>
#include <optional>
#include <print>
#include <regex>
#include <stdexcept>
#include <string>

namespace utils {

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

inline std::optional<uint32_t> parse_time_scale(const std::string& time_str) {
    std::regex pattern(R"((\d+)(s|ms|m))");
    std::smatch match;
    if (std::regex_match(time_str, match, pattern)) {
        uint32_t base = std::stoul(match[1].str());
        std::string unit = match[2].str();
        if (unit == "ms")
            return base / 1000;
        if (unit == "m")
            return base * 60;
        return base; // "s"
    }
    return std::nullopt;
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

inline void todo(const std::string& str) {
    throw std::runtime_error(str);
}

inline void todo() {
    throw std::runtime_error("Not implementation\n");
}

template<typename... Args>
[[noreturn]] inline void panic(std::format_string<Args...> fmt, Args&&... args) {
    std::string msg = std::format(fmt, std::forward<Args>(args)...);
    std::println(stderr, "panic at '{}':{}", __builtin_FILE(), __builtin_LINE());
    std::println(stderr, "    {}", msg);

    std::array<void*, 32> trace {};
    int size = ::backtrace(trace.data(), 32);
    char** symbols = ::backtrace_symbols(trace.data(), size);

    std::println(stderr, "\nStack trace:");
    for (int i = 0; i < size; ++i)
        std::println(stderr, "  {}", symbols[i]);

    std::free(static_cast<void*>(symbols));
    std::abort();
}

} // namespace utils
