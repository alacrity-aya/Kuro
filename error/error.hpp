#pragma once

#include <cstdint>
#include <string>

namespace module_error {

enum class ModuleError : uint8_t {
    OPEN_AND_LOAD_BPF_FAILED,
    POLL_RINGBUF_FAILED,
    ATTACH_BPF_FAILED,
    LOCAL_IP_MAP_SETUP_FAILED,
    NETFILTER_HOOK_ATTACH_FAILED,
    RING_BUFFER_INIT_FAILED,
    FAILED_TO_UPDATE_MAP,
    FAILED_TO_FIND_MAP,
    FAILED_TO_FIND_BPF_PROG
};

inline std::string error_to_string(ModuleError err) {
    switch (err) {
        case ModuleError::POLL_RINGBUF_FAILED:
            return "Poll ring buffer failed.";
        case ModuleError::ATTACH_BPF_FAILED:
            return "Failed to attach bpf program";
        case ModuleError::OPEN_AND_LOAD_BPF_FAILED:
            return "Failed to open skel."; // This covers open and load failure
        case ModuleError::LOCAL_IP_MAP_SETUP_FAILED:
            return "Failed to initialize or update the local IP map.";
        case ModuleError::NETFILTER_HOOK_ATTACH_FAILED:
            return "Failed to attach the BPF program to the netfilter hook.";
        case ModuleError::RING_BUFFER_INIT_FAILED:
            return "Failed to initialize the ring buffer for data communication.";
        case ModuleError::FAILED_TO_UPDATE_MAP:
            return "Failed to update an element in a BPF map.";
        case ModuleError::FAILED_TO_FIND_MAP:
            return "Failed to find bpf map";
        case ModuleError::FAILED_TO_FIND_BPF_PROG:
            return "Failed to find bpf program";
    }
    // Default case for completeness, although all enums should be covered.
    return "Unknown Module Error";
}
} // namespace module_error
