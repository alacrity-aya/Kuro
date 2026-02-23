#pragma once

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// =============================================================
// Log Level Definitions
// =============================================================
#define LOG_DEBUG 0
#define LOG_INFO 1
#define LOG_WARN 2
#define LOG_ERROR 3

// Log switch (compile-time control)
#define ENABLE_LOG 1

// Maximum log message length
#define LOG_MSG_LEN 256

// =============================================================
// Ringbuf Map Definition
// =============================================================
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1MB
} log_ringbuf SEC(".maps");

// =============================================================
// Log Output Macro
// =============================================================
#if ENABLE_LOG
    #define KURO_LOG(level, fmt, ...) \
        do { \
            char msg[LOG_MSG_LEN] = { 0 }; \
            BPF_SNPRINTF(msg, sizeof(msg), "[BPF-" #level "] " fmt, ##__VA_ARGS__); \
            bpf_ringbuf_output(&log_ringbuf, msg, LOG_MSG_LEN, 0); \
        } while (0)
#else
    #define KURO_LOG(level, fmt, ...)
#endif

// Convenience macros (override existing kuro_debug in helper.h)
#define kuro_debug(fmt, ...) KURO_LOG(DEBUG, fmt, ##__VA_ARGS__)
#define kuro_info(fmt, ...) KURO_LOG(INFO, fmt, ##__VA_ARGS__)
#define kuro_warn(fmt, ...) KURO_LOG(WARN, fmt, ##__VA_ARGS__)
#define kuro_error(fmt, ...) KURO_LOG(ERROR, fmt, ##__VA_ARGS__)
