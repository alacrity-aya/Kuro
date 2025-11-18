#pragma once

#include <cstdint>
#include <expected>
#include <format>
#include <source_location>
#include <string>
#include <utility>

namespace error {

enum class ErrorCode : uint8_t {
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
    FAILED_TO_GET_CGROUP_FD
};

inline std::string error_to_string(ErrorCode err) {
    switch (err) {
        case ErrorCode::POLL_RINGBUF_FAILED:
            return "Poll ring buffer failed.";
        case ErrorCode::FAILED_TO_GET_CGROUP_FD:
            return "Failed to find cgroup fd";
        case ErrorCode::RUN_SHELL_CMD_FAILED:
            return "Shell command failed";
        case ErrorCode::EMPTY_RULE:
            return "Rule is empty, initialize it first";
        case ErrorCode::PARSING_CONFIG_FAILED:
            return "Parsing config failed.";
        case ErrorCode::EMPTY_CONFIG_NODE:
            return "Config node is empty.";
        case ErrorCode::ATTACH_BPF_FAILED:
            return "Failed to attach bpf program.";
        case ErrorCode::OPEN_AND_LOAD_BPF_FAILED:
            return "Failed to open skel."; // This covers open and load failure
        case ErrorCode::LOCAL_IP_MAP_SETUP_FAILED:
            return "Failed to initialize or update the local IP map.";
        case ErrorCode::NETFILTER_HOOK_ATTACH_FAILED:
            return "Failed to attach the BPF program to the netfilter hook.";
        case ErrorCode::RING_BUFFER_INIT_FAILED:
            return "Failed to initialize the ring buffer for data communication.";
        case ErrorCode::FAILED_TO_UPDATE_MAP:
            return "Failed to update an element in a BPF map.";
        case ErrorCode::FAILED_TO_FIND_MAP:
            return "Failed to find bpf map";
        case ErrorCode::FAILED_TO_FIND_BPF_PROG:
            return "Failed to find bpf program";
    }
    // Default case for completeness, although all enums should be covered.
    return "Unknown Module Error";
}

struct ModuleError {
public:
    explicit ModuleError(
        ErrorCode code,
        std::string msg = "",
        std::source_location loc = std::source_location::current()
    ):
        code { code },
        loc { loc },
        msg { std::move(msg) } {}

    [[nodiscard]] std::string to_string() const {
        auto base_msg = error_to_string(code);
        return std::format(
            "at {}:{} in {}: {} {}",
            loc.file_name(),
            loc.line(),
            loc.function_name(),
            base_msg,
            msg
        );
    }

private:
    ErrorCode code;
    const std::source_location loc;
    std::string msg;
};

using ModuleResult = std::expected<void, ModuleError>;
} // namespace error
