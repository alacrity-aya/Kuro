#pragma once

#include <cstdint>
#include <expected>
#include <format>
#include <map>
#include <source_location>
#include <string>
#include <utility>

namespace std {

template<>
struct formatter<std::source_location, char> {
    static constexpr auto parse(format_parse_context& ctx) {
        return ctx.begin();
    }

    static auto format(const std::source_location& loc, format_context& ctx) {
        return format_to(
            ctx.out(),
            "at {}:{} in {}",
            loc.file_name(),
            loc.line(),
            loc.function_name()
        );
    }
};

} // namespace std

namespace error {

enum class ErrorCode : uint8_t {
    // BPF/IO ERROR
    OPEN_AND_LOAD_BPF_FAILED,
    POLL_RINGBUF_FAILED,
    ATTACH_BPF_FAILED,
    LOCAL_IP_MAP_SETUP_FAILED,
    NETFILTER_HOOK_ATTACH_FAILED,
    RING_BUFFER_INIT_FAILED,
    FAILED_TO_UPDATE_MAP,
    FAILED_TO_FIND_MAP,
    FAILED_TO_FIND_BPF_PROG,
    EMPTY_CONFIG_NODE,
    EMPTY_RULE,
    PARSING_CONFIG_FAILED,
    RUN_SHELL_CMD_FAILED,
    FAILED_TO_GET_CGROUP_FD,

    // PARSE ERROR
    PARSE_MISSING_REQUIRED_FIELD,
    PARSE_INVALID_IP,
    PARSE_INVALID_PORT,
    PARSE_INVALID_PROTO,
    PARSE_INVALID_GRESS,
    PARSE_INVALID_RATE,
    PARSE_INVALID_TIME_SCALE,

    // UNKNOWN ERROR
    UNKNOWN_ERROR_CODE
};

inline std::string error_to_string(ErrorCode err) {
    static std::map<ErrorCode, std::string> error_map = {
        // --- BPF/IO error ---
        { ErrorCode::OPEN_AND_LOAD_BPF_FAILED,
          "BPF object failed to open and load its programs/maps." },
        { ErrorCode::POLL_RINGBUF_FAILED, "Failed to poll the BPF ring buffer for data events." },
        { ErrorCode::ATTACH_BPF_FAILED, "Failed to attach BPF program to its hook point." },
        { ErrorCode::LOCAL_IP_MAP_SETUP_FAILED,
          "BPF Local IP map initialization or update failed." },
        { ErrorCode::NETFILTER_HOOK_ATTACH_FAILED,
          "Failed to attach BPF program to a Netfilter hook." },
        { ErrorCode::RING_BUFFER_INIT_FAILED, "BPF Ring Buffer initialization failed." },
        { ErrorCode::FAILED_TO_UPDATE_MAP, "Failed to update an entry in a BPF map." },
        { ErrorCode::FAILED_TO_FIND_MAP, "BPF Map not found in the loaded BPF object." },
        { ErrorCode::FAILED_TO_FIND_BPF_PROG, "BPF Program not found in the loaded BPF object." },
        { ErrorCode::EMPTY_CONFIG_NODE, "Configuration node is empty or missing required data." },
        { ErrorCode::EMPTY_RULE, "Configuration rule is empty or requires initialization." },
        { ErrorCode::PARSING_CONFIG_FAILED, "Failed to parse the configuration file/data." },
        { ErrorCode::RUN_SHELL_CMD_FAILED, "Execution of an external shell command failed." },
        { ErrorCode::FAILED_TO_GET_CGROUP_FD,
          "Failed to obtain the file descriptor for the cgroup path." },

        // --- ParseError ---
        { ErrorCode::PARSE_MISSING_REQUIRED_FIELD,
          "Required configuration field is missing or empty." },
        { ErrorCode::PARSE_INVALID_IP, "IP address format is invalid (expected IPv4 or IPv6)." },
        { ErrorCode::PARSE_INVALID_PORT,
          "Port number is invalid (expected value between 1 and 65535)." },
        { ErrorCode::PARSE_INVALID_PROTO,
          "Protocol value is invalid (only 'TCP', 'UDP', or 'ICMP' are supported)." },
        { ErrorCode::PARSE_INVALID_GRESS,
          "Traffic direction ('Gress') value is invalid (expected 'ingress' or 'egress')." },
        { ErrorCode::PARSE_INVALID_RATE,
          "Rate limit format is invalid (expected bandwidth units, e.g., '10Mbps', '1G')." },
        { ErrorCode::PARSE_INVALID_TIME_SCALE,
          "Time scale format is invalid (expected time units, e.g., '100ms', '5s', '1m')." },

        // --- unknown error ---
        { ErrorCode::UNKNOWN_ERROR_CODE, "An unclassified or unknown module error occurred." }
    };

    if (error_map.contains(err)) {
        return error_map[err];
    }

    return "Unknown Error Code (" + std::to_string(static_cast<uint8_t>(err)) + ").";
}

struct Error {
public:
    explicit Error(
        ErrorCode code,
        std::string msg = "",
        std::source_location loc = std::source_location::current()
    ):
        code { code },
        loc { loc },
        msg { std::move(msg) } {}

    [[nodiscard]] std::string to_string() const {
        auto base_msg = error_to_string(code);
        return std::format("{}: {} {}", loc, base_msg, msg);
    }

private:
    ErrorCode code;
    const std::source_location loc;
    std::string msg;
};

using Result = std::expected<void, Error>;
} // namespace error
