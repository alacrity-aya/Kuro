#pragma once

#include "error/error.hpp"
#include "logger/logger.hpp"
#include <arpa/inet.h>
#include <cpptrace/cpptrace.hpp>
#include <expected>
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

[[noreturn]]
inline void todo(const std::source_location& loc = std::source_location::current()) {
    panic("Not implemented", loc);
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
    // return "hello"; // uncomment this for debugging

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

struct CommandResult {
    std::string output;
    int exitstatus;
    friend std::ostream& operator<<(std::ostream& os, const CommandResult& result) {
        os << "command exitstatus: " << result.exitstatus << " output: " << result.output;
        return os;
    }
    bool operator==(const CommandResult& rhs) const {
        return output == rhs.output && exitstatus == rhs.exitstatus;
    }
    bool operator!=(const CommandResult& rhs) const {
        return !(rhs == *this);
    }
};

class Command {
public:
    /**
             * Execute system command and get STDOUT result.
             * Regular system() only gives back exit status, this gives back output as well.
             * @param command system command to execute
             * @return commandResult containing STDOUT (not stderr) output & exitstatus
             * of command. Empty if command failed (or has no output). If you want stderr,
             * use shell redirection (2&>1).
             */
    static std::expected<CommandResult, std::string> exec(const std::string& command) {
        int exitcode = 0;
        std::array<char, 1048576> buffer {};
        std::string result;
#ifdef _WIN32
    #define popen _popen
    #define pclose _pclose
    #define WEXITSTATUS
#endif
        FILE* pipe = popen(command.c_str(), "r");
        if (pipe == nullptr) {
            return std::unexpected { "popen() failed" };
        }
        try {
            std::size_t bytesread;
            while ((bytesread =
                        std::fread(buffer.data(), sizeof(buffer.at(0)), sizeof(buffer), pipe))
                   != 0)
            {
                result += std::string(buffer.data(), bytesread);
            }
        } catch (...) {
            pclose(pipe);
            return std::unexpected { "std::fread() failed" };
            throw;
        }
        exitcode = WEXITSTATUS(pclose(pipe));
        return CommandResult { .output = result, .exitstatus = exitcode };
    }
};

static bool
log_exec_result(std::expected<CommandResult, std::string> result, std::string_view cmd) {
    auto& logger = logger::Logger::instance();

    if (!result.has_value()) {
        logger.warn("{} failed, {}, please run this cmd manually", cmd, result.error());
        return false;
    }
    logger.trace("{}", result.value());
    return true;
}

// TODO(alacrity): the following two functions need to be refactored
using error::ModuleResult;
inline ModuleResult
service_start(const std::string& path, const std::string& args, const std::string& uuid) {
    auto cmd = std::format(
        "sudo systemd-run --unit={} --property=Slice=limit.slice --property=Description=Kuro-Flow-Control {} {}",
        uuid,
        path,
        args
    );
    auto result = Command::exec(cmd);

    if (!log_exec_result(result, cmd)) {
        return std::unexpected {
            error::ModuleError { error::ErrorCode::RUN_SHELL_CMD_FAILED, cmd + " failed" },
        };
    }
    return {};
}

inline std::optional<int> get_cgroup_fd(const std::string& uuid) {
    auto ret = open(std::format("/sys/fs/cgroup/limit.slice/{}.service", uuid).c_str(), O_RDONLY);
    if (ret == 0) {
        return std::nullopt;
    }
    return ret;
}

inline void service_status(const std::string& uuid) {
    auto cmd = std::format("sudo systemctl status {}", uuid);
    auto result = Command::exec(cmd);
    log_exec_result(result, cmd);
}

inline void service_stop(const std::string& uuid) {
    // sudo systemctl reset-failed 56c0cb1e-8116-4e83-95e9-b37e5ffb2bd8
    auto reset_failed = std::format("sudo systemctl reset-failed {}", uuid);
    auto result1 = Command::exec(reset_failed);
    log_exec_result(result1, reset_failed);

    auto stop = std::format("sudo systemctl stop {}", uuid);
    auto result2 = Command::exec(stop);
    log_exec_result(result2, stop);
}

} // namespace utils

namespace std {

template<>
struct formatter<utils::CommandResult, char> {
    static constexpr auto parse(format_parse_context& ctx) {
        return ctx.begin();
    }

    static auto format(const utils::CommandResult& cr, format_context& ctx) {
        return format_to(ctx.out(), "command exitstatus: {} output: {}", cr.exitstatus, cr.output);
    }
};

} // namespace std
