#pragma once

#include "map.h"
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_UNSPEC -1

#define NSEC_PER_SEC 1000000000ULL
#define DEFAULT_EDT_HORIZON_NS (2ULL * NSEC_PER_SEC)

#define ENABLE_PRINT 1

#if ENABLE_PRINT
    #define kuro_debug(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
    #define kuro_debug(fmt, ...)
#endif

static __always_inline void get_global_config(__u64* horizon) {
    __u32 key = 0;

    struct global_config* cfg = bpf_map_lookup_elem(&config_map, &key);

    if (cfg && cfg->edt_horizon_ns > 0) {
        *horizon = cfg->edt_horizon_ns;
    } else {
        *horizon = DEFAULT_EDT_HORIZON_NS;
    }
}
