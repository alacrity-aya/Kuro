# BPF Ringbuf Logging System Design

## Overview

This document describes the design for a logging system in the eBPF layer using ringbuf. The system enables structured logging from kernel space with minimal overhead, following the principle of "kernel space formats strings, user space outputs directly."

## Requirements

| Aspect | Decision |
|--------|----------|
| Purpose | Development debugging (can be disabled in production) |
| Log Levels | 4 levels: `[DEBUG]`, `[INFO]`, `[WARN]`, `[ERROR]` |
| Format | Text-based, e.g., `[DEBUG] Sim Upload: 10.0.0.1:8080 -> 10.0.0.2:443` |
| Kernel Formatting | Use `bpf_snprintf` for string formatting |
| Code Separation | Log code isolated from existing helper.h and manager.go |

## Architecture

### File Organization

```
bpf/
├── tc.c              # Existing file, add #include "log.h" and log calls
└── include/
    ├── map.h         # Unchanged
    ├── helper.h      # Unchanged
    └── log.h         # [NEW] Logging definitions (map, levels, macros)

internal/agent/bpf/
├── manager.go        # Unchanged
└── logger.go         # [NEW] Independent log reader
```

### Data Flow

```
┌─────────────────────────────────────────────────────────┐
│                    KERNEL SPACE                          │
│  tc.c: handle_edt_upload() etc.                         │
│      │                                                   │
│      ▼                                                   │
│  log.h: kuro_debug("fmt", args)                         │
│      │                                                   │
│      ▼                                                   │
│  bpf_snprintf() → char msg[256]                         │
│      │                                                   │
│      ▼                                                   │
│  bpf_ringbuf_output(&log_ringbuf, msg, len, 0)          │
└─────────────────────────────────────────────────────────┘
                         │
                   Ring Buffer
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│                    USER SPACE                            │
│  logger.go: Logger                                       │
│      │                                                   │
│      ▼                                                   │
│  ringbuf.Reader.Read()                                   │
│      │                                                   │
│      ▼                                                   │
│  fmt.Fprintf(output, "%s\n", msg)                       │
└─────────────────────────────────────────────────────────┘
```

## Implementation Details

### Kernel Space (log.h)

```c
#pragma once
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// =============================================================
// Log Level Definitions
// =============================================================
#define LOG_DEBUG 0
#define LOG_INFO  1
#define LOG_WARN  2
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
    __uint(max_entries, 1 << 20);  // 1MB
} log_ringbuf SEC(".maps");

// =============================================================
// Log Output Macro
// =============================================================
#if ENABLE_LOG
    #define KURO_LOG(level, fmt, ...)                                       \
        do {                                                                \
            char msg[LOG_MSG_LEN];                                          \
            int len = bpf_snprintf(msg, sizeof(msg),                        \
                "[" #level "] " fmt, ##__VA_ARGS__);                        \
            if (len > 0) {                                                  \
                bpf_ringbuf_output(&log_ringbuf, msg, len, 0);              \
            }                                                               \
        } while (0)
#else
    #define KURO_LOG(level, fmt, ...) 
#endif

// Convenience macros (override existing kuro_debug in helper.h)
#define kuro_debug(fmt, ...) KURO_LOG(DEBUG, fmt, ##__VA_ARGS__)
#define kuro_info(fmt, ...)  KURO_LOG(INFO, fmt, ##__VA_ARGS__)
#define kuro_warn(fmt, ...)  KURO_LOG(WARN, fmt, ##__VA_ARGS__)
#define kuro_error(fmt, ...) KURO_LOG(ERROR, fmt, ##__VA_ARGS__)
```

### User Space (logger.go)

```go
package bpf

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// Logger is an independent BPF log reader
type Logger struct {
	reader *ringbuf.Reader
	output io.Writer
	done   chan struct{}
}

// NewLogger creates a log reader from the ringbuf map
func NewLogger(ringbufMap *ebpf.Map, output io.Writer) (*Logger, error) {
	reader, err := ringbuf.NewReader(ringbufMap)
	if err != nil {
		return nil, fmt.Errorf("create ringbuf reader: %w", err)
	}

	if output == nil {
		output = os.Stdout
	}

	return &Logger{
		reader: reader,
		output: output,
		done:   make(chan struct{}),
	}, nil
}

// Start begins consuming log messages
func (l *Logger) Start() {
	go func() {
		for {
			select {
			case <-l.done:
				return
			default:
				record, err := l.reader.Read()
				if err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						return
					}
					continue
				}

				// Output formatted string directly from kernel
				msg := bytes.TrimRight(record.RawSample, "\x00")
				fmt.Fprintf(l.output, "%s\n", msg)
			}
		}
	}()
}

// Stop closes the log reader
func (l *Logger) Stop() {
	close(l.done)
	l.reader.Close()
}
```

### Usage in tc.c

```c
#include "include/helper.h"
#include "include/map.h"
#include "include/log.h"  // Must be last to override kuro_debug

SEC("tc/edt_upload")
int handle_edt_upload(struct __sk_buff* skb) {
    // ... existing code ...
    
    if (is_sim_traffic) {
        kuro_debug("Sim Upload: %pI4:%u -> %pI4:%u", 
                   &src_ip, src_port, &dst_ip, dst_port);
    }
    
    if (ret == TC_ACT_SHOT) {
        kuro_warn("Queue overflow: ifindex=%u horizon=%llu", ifindex, horizon_ns);
    }
    
    // ...
}
```

### Usage in Agent Startup

```go
// In agent initialization
logger, err := bpf.NewLogger(coll.Maps["log_ringbuf"], os.Stdout)
if err != nil {
    log.Fatalf("Failed to create logger: %v", err)
}
logger.Start()
defer logger.Stop()
```

## Future Extensions

### Runtime Log Level Filtering

A BPF map can be added for runtime log level control:

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);  // Current log level threshold
    __uint(max_entries, 1);
} log_level_map SEC(".maps");

// Modified macro with level check
#define KURO_LOG(level, fmt, ...)                                          \
    do {                                                                   \
        __u32 key = 0;                                                     \
        __u32 *threshold = bpf_map_lookup_elem(&log_level_map, &key);      \
        if (!threshold || LOG_##level < *threshold) break;                 \
        /* ... existing logic ... */                                       \
    } while (0)
```

## Summary

| Component | File | Changes |
|-----------|------|---------|
| Kernel log definitions | `bpf/include/log.h` | New file |
| Kernel log calls | `bpf/tc.c` | Add `#include "log.h"`, replace `kuro_debug` calls |
| User space reader | `internal/agent/bpf/logger.go` | New file |
| Agent startup | `internal/agent/agent.go` | Initialize logger |
