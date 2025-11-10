#pragma once

#include <cstdint>
#include <string>

namespace module_error {

enum class ModuleError : uint8_t {
    ROOT_PRIVILEGES_REQUIRED,
    FAILED_TO_OPEN_BPF_OBJECT,
    FAILED_TO_LOAD_BPF_OBJECT,
    LOCAL_IP_MAP_SETUP_FAILED,
    NETFILTER_HOOK_ATTACH_FAILED,
    KPROBE_HOOK_ATTACH_FAILED,
    RING_BUFFER_INIT_FAILED,
    PROCESS_RULES_MAP_NOT_FOUND,
    FAILED_TO_UPDATE_MAP,
    FAILED_TO_FIND_PROJECT_ROOT,
    FAILED_TO_FIND_MAP,
    FAILED_TO_FIND_BPF_PROG,
    UNKNOWN_ERROR
};

inline std::string error_to_string(ModuleError err) {
    switch (err) {
        case ModuleError::ROOT_PRIVILEGES_REQUIRED:
            return "Root privileges are required to run this module.";
        case ModuleError::FAILED_TO_OPEN_BPF_OBJECT:
            return "Failed to open BPF object file.";
        case ModuleError::FAILED_TO_LOAD_BPF_OBJECT:
            return "Failed to load BPF object into the kernel.";
        case ModuleError::LOCAL_IP_MAP_SETUP_FAILED:
            return "Failed to initialize or update the local IP map.";
        case ModuleError::NETFILTER_HOOK_ATTACH_FAILED:
            return "Failed to attach the BPF program to the netfilter hook.";
        case ModuleError::KPROBE_HOOK_ATTACH_FAILED:
            return "Failed to attach the BPF program to the kprobe.";
        case ModuleError::RING_BUFFER_INIT_FAILED:
            return "Failed to initialize the ring buffer for data communication.";
        case ModuleError::PROCESS_RULES_MAP_NOT_FOUND:
            return "The 'process_rules' BPF map could not be found.";
        case ModuleError::FAILED_TO_UPDATE_MAP:
            return "Failed to update an element in a BPF map.";
        case ModuleError::FAILED_TO_FIND_PROJECT_ROOT:
            return "Failed to find project root.";
        case ModuleError::FAILED_TO_FIND_MAP:
            return "Failed to find bpf map";
        case ModuleError::FAILED_TO_FIND_BPF_PROG:
            return "Failed to find bpf program";
        case ModuleError::UNKNOWN_ERROR:
            // Fallthrough to the default return is usually better for UNKNOWN_ERROR,
            // but explicitly returning is also fine.
            return "An unclassified or unknown module error occurred.";
    }
    // Default case for completeness, although all enums should be covered.
    return "Unknown Module Error";
}
} // namespace module_error
