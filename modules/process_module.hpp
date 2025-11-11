#pragma once
#include <arpa/inet.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <error/error.hpp>
#include <expected>
#include <fcntl.h>
#include <getopt.h>
#include <linux/netfilter.h>
#include <net/if.h>
#include <nlohmann/json.hpp>
#include <print>
#include <string>
#include <sys/syscall.h>
#include <tc_process.skel.h>
#include <unistd.h>
#include <utils.hpp>

namespace process_module {
using module_error::ModuleError;

using ModuleResult = std::expected<void, ModuleError>;

struct ProcessRule {
    uint32_t target_pid;
    uint64_t rate_bps;
    uint8_t gress;
    uint32_t time_scale;
};

struct ProcInfo {
    __u32 pid;
    std::array<char, 16> comm;
};

struct MessageGet {
    __u64 instance_rate_bps;
    __u64 rate_bps;
    __u64 peak_rate_bps;
    __u64 smoothed_rate_bps;
    struct ProcInfo proc;
    __u64 timestamp;
};

class ProcessModule {
public:
    ProcessModule() = default;
    ~ProcessModule() {
        unload();
    }

    ModuleResult load() {
        // Is it a good implementation? I have no idea about this.
        // Anyway, it looks good.
        libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

        auto open_and_load_bpf = [this]() -> ModuleResult {
            skel = tc_process__open_and_load();
            if (skel == nullptr) {
                return std::unexpected { ModuleError::OPEN_AND_LOAD_BPF_FAILED };
            }
            return {};
        };

        return open_and_load_bpf()
            .and_then([this]() -> ModuleResult {
                if (tc_process__attach(skel) != 0) {
                    return std::unexpected { ModuleError::ATTACH_BPF_FAILED };
                }
                return {};
            })
            .and_then([this]() { return setup_local_ip_map(); })
            .and_then([this]() { return attach_netfilter_hook(); })
            .and_then([this]() { return init_ring_buffer(); });
    }

    void unload() {
        if (rb_ != nullptr) {
            ring_buffer__free(rb_);
            rb_ = nullptr;
        }

        tc_process__destroy(skel);
    }

    ModuleResult update_rule(const ProcessRule& rule) {
        auto* map = skel->maps.process_rules;
        if (map == nullptr) {
            // Changed: process_rules map not found
            std::println("[process_module] 'process_rules' map not found");
            return std::unexpected { ModuleError::FAILED_TO_FIND_MAP };
        }

        uint32_t key = 0;
        int err = bpf_map__update_elem(map, &key, sizeof(key), &rule, sizeof(rule), BPF_ANY);
        if (err != 0) {
            // Changed: Failed to update process_rules
            std::println("[process_module] Failed to update process_rules: {}", err);
            return std::unexpected { ModuleError::FAILED_TO_UPDATE_MAP };
        }
        return {};
    }

    //poll ring buffer once, omitting ctrl-c in this function
    ModuleResult poll_ring_buffer(int timeout_ms) {
        auto err = ring_buffer__poll(rb_, timeout_ms);
        if (err < 0 && err != -EINTR) {
            return std::unexpected { ModuleError::POLL_RINGBUF_FAILED };
        }
        return {};
    }

private:
    struct ring_buffer* rb_ = nullptr;
    tc_process* skel {};
    struct bpf_link* recvmsg_kprobe_ = nullptr;
    struct bpf_link* sendmsg_kprobe_ = nullptr;

    static int handle_event(void*, void* data, size_t data_sz) {
        if (data_sz != sizeof(MessageGet)) {
            std::println("Data size mismatch: {} (expected {})", data_sz, sizeof(MessageGet));
            return 0;
        }

        const auto* e = static_cast<const MessageGet*>(data);

        std::print("\033[2J\033[H");

        std::println("=== process_traffic ===");
        std::println(
            " instant_rate_bps : {:.2f} MB/s",
            static_cast<double>(e->instance_rate_bps) / 1024.0 / 1024.0
        );
        std::println(
            " rate_bps         : {:.2f} MB/s",
            static_cast<double>(e->rate_bps) / 1024.0 / 1024.0
        );
        std::println(
            " peak_rate_bps    : {:.2f} MB/s",
            static_cast<double>(e->peak_rate_bps) / 1024.0 / 1024.0
        );
        std::println(
            " smoothed_rate_bps: {:.2f} MB/s",
            static_cast<double>(e->smoothed_rate_bps) / 1024.0 / 1024.0
        );
        std::println("=====================");

        // 手动刷新标准输出缓冲区
        std::fflush(stdout);

        return 0;
    }

    ModuleResult setup_local_ip_map() {
        auto* map = skel->maps.local_ip_map;
        if (map == nullptr) {
            // Changed: local_ip_map not found
            std::println("'local_ip_map' not found");
            return std::unexpected { ModuleError::FAILED_TO_FIND_MAP };
        }

        std::string local_ip = get_local_ip_address();
        // Changed: local IP output
        std::println("local IP: {}", local_ip);

        uint32_t key = 0;
        uint32_t ip_addr = inet_addr(local_ip.c_str());
        int err = bpf_map__update_elem(map, &key, sizeof(key), &ip_addr, sizeof(ip_addr), BPF_ANY);
        if (err != 0) {
            // Changed: Failed to update local_ip_map
            std::println("Failed to update 'local_ip_map': {}", err);
            return std::unexpected { ModuleError::FAILED_TO_UPDATE_MAP };
        }
        return {};
    }

    static std::string get_local_ip_address() {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0)
            return "127.0.0.1";

        struct sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = inet_addr("8.8.8.8");
        addr.sin_port = htons(53);
        if (connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
            close(sock);
            return "127.0.0.1";
        }

        socklen_t len = sizeof(addr);
        if (getsockname(sock, reinterpret_cast<struct sockaddr*>(&addr), &len) < 0) {
            close(sock);
            return "127.0.0.1";
        }

        close(sock);
        std::array<char, INET_ADDRSTRLEN> ip_str;
        inet_ntop(AF_INET, &addr.sin_addr, ip_str.data(), INET_ADDRSTRLEN);
        return { ip_str.data() };
    }

    ModuleResult attach_netfilter_hook() {
        auto* prog = skel->progs.netfilter_hook;
        if (prog == nullptr)
            return std::unexpected { ModuleError::FAILED_TO_FIND_BPF_PROG };

        // TODO(alacrity): add NF_INET_LOCAL_IN
        struct bpf_netfilter_opts opts = {
            .sz = sizeof(opts),
            .pf = NFPROTO_IPV4,
            .hooknum = NF_INET_LOCAL_OUT,
            .priority = -128,
        };
        auto* nf_link_out = bpf_program__attach_netfilter(prog, &opts);
        if (libbpf_get_error(nf_link_out) != 0) {
            std::println("Failed to attach netfilter hook");
            return std::unexpected { ModuleError::NETFILTER_HOOK_ATTACH_FAILED };
        }

        opts.hooknum = NF_INET_LOCAL_IN;
        auto* nf_link_in = bpf_program__attach_netfilter(prog, &opts);
        if (libbpf_get_error(nf_link_out) != 0) {
            std::println("Failed to attach netfilter hook");
            return std::unexpected { ModuleError::NETFILTER_HOOK_ATTACH_FAILED };
        }

        return {};
    }

    ModuleResult init_ring_buffer() {
        auto* map = skel->maps.ringbuf;
        if (map == nullptr)
            return std::unexpected { ModuleError::FAILED_TO_FIND_MAP };

        int map_fd = bpf_map__fd(map);
        rb_ = ring_buffer__new(map_fd, handle_event, nullptr, nullptr);
        if (rb_ == nullptr) {
            return std::unexpected { ModuleError::RING_BUFFER_INIT_FAILED };
        }
        return {};
    }
};

} // namespace process_module
