#pragma once

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_UNSPEC -1

#define NSEC_PER_SEC 1000000000ULL

#define DEFAULT_EDT_HORIZON_NS (2ULL * NSEC_PER_SEC)
#define DEFAULT_TBF_BURST_BYTES (100 * 1024)

__always_inline __u64 min_u64(__u64 a, __u64 b) {
    return a < b ? a : b;
}

__always_inline __u64 max_u64(__u64 a, __u64 b) {
    return a > b ? a : b;
}
