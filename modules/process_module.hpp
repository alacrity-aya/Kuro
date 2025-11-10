#pragma once
#include <arpa/inet.h>
#include <array>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/libbpf_legacy.h>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <error/error.hpp>
#include <expected>
#include <fcntl.h>
#include <filesystem>
#include <getopt.h>
#include <linux/bpf.h>
#include <linux/netfilter.h>
#include <net/if.h>
#include <nlohmann/json.hpp>
#include <print>
#include <string>
#include <sys/syscall.h>
#include <unistd.h>
#include <utils.hpp>
#include <yaml-cpp/yaml.h>

namespace process_module {
using module_error::ModuleError;

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

    std::expected<void, ModuleError> load(const std::filesystem::path& project_root) {
        // Is it a good implementation? I have no idea about this.
        // Anyway, it looks good.
        auto tc_process_path = project_root / "bpf" / "build" / "tc_process.o";
        return open_bpf_obj(tc_process_path)
            .and_then([this]() { return load_bpf_obj(); })
            .and_then([this]() { return attach_probe("security_socket_recvmsg", recvmsg_kprobe_); })
            .and_then([this]() { return attach_probe("security_socket_sendmsg", sendmsg_kprobe_); })
            .and_then([this]() { return setup_local_ip_map(); })
            .and_then([this]() { return attach_netfilter_hook(); })
            .and_then([this]() { return init_ring_buffer(); });
    }

    void unload() {
        if (rb_ != nullptr) {
            ring_buffer__free(rb_);
            rb_ = nullptr;
        }
        if (recvmsg_kprobe_ != nullptr) {
            bpf_link__destroy(recvmsg_kprobe_);
            recvmsg_kprobe_ = nullptr;
        }
        if (sendmsg_kprobe_ != nullptr) {
            bpf_link__destroy(sendmsg_kprobe_);
            sendmsg_kprobe_ = nullptr;
        }
        if (nf_fd_ingress_ >= 0)
            close(nf_fd_ingress_);
        if (nf_fd_egress_ >= 0)
            close(nf_fd_egress_);
        if (obj_ != nullptr) {
            bpf_object__close(obj_);
            obj_ = nullptr;
        }
    }

    std::expected<void, ModuleError> update_rule(const ProcessRule& rule) {
        auto* map = bpf_object__find_map_by_name(obj_, "process_rules");
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

    struct ring_buffer* rb_ = nullptr; // TODO(alacrity):  shoule be private

private:
    struct bpf_object* obj_ = nullptr;
    struct bpf_link* recvmsg_kprobe_ = nullptr;
    struct bpf_link* sendmsg_kprobe_ = nullptr;
    int nf_fd_ingress_ = -1;
    int nf_fd_egress_ = -1;

    static int handle_event(void*, void* data, size_t data_sz) {
        if (data_sz != sizeof(MessageGet)) {
            // Changed: Data size mismatch
            std::println("Data size mismatch: {} (expected {})", data_sz, sizeof(MessageGet));
            return 0;
        }
        const auto* e = static_cast<const MessageGet*>(data);

        // Changed: Use std::println with formatting
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

        return 0;
    }

    std::expected<void, ModuleError> setup_local_ip_map() {
        struct bpf_map* map = bpf_object__find_map_by_name(obj_, "local_ip_map");
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

    std::expected<void, ModuleError> open_bpf_obj(const std::filesystem::path& path) {
        obj_ = bpf_object__open_file(path.c_str(), nullptr);
        if ((obj_ == nullptr) || (libbpf_get_error(obj_) != 0)) {
            // Changed: Failed to open BPF object
            std::println("[process_module] Failed to open BPF object");
            return std::unexpected { ModuleError::FAILED_TO_OPEN_BPF_OBJECT };
        }
        return {};
    }

    std::expected<void, ModuleError> load_bpf_obj() {
        if (bpf_object__load(obj_) != 0) {
            // Changed: Failed to load BPF object
            std::println("[process_module] Failed to load BPF object");
            bpf_object__close(obj_);
            obj_ = nullptr;
            return std::unexpected { ModuleError::FAILED_TO_LOAD_BPF_OBJECT };
        }
        return {};
    }

    std::expected<void, ModuleError> attach_probe(const char* prog_name, struct bpf_link*& link) {
        auto* prog = bpf_object__find_program_by_name(obj_, prog_name);
        if (prog == nullptr)
            return std::unexpected { ModuleError::FAILED_TO_FIND_BPF_PROG };
        link = bpf_program__attach_kprobe(prog, false, prog_name);
        if (link == nullptr) {
            // Changed: attach kprobe failed
            std::println("[process_module] Failed to attach kprobe: {}", prog_name);
            return std::unexpected { ModuleError::KPROBE_HOOK_ATTACH_FAILED };
        }
        return {};
    }

    std::expected<void, ModuleError> attach_netfilter_hook() {
        auto* prog = bpf_object__find_program_by_name(obj_, "netfilter_hook");
        if (prog == nullptr)
            return std::unexpected { ModuleError::FAILED_TO_FIND_BPF_PROG };

        // TODO(alacrity): add NF_INET_LOCAL_IN
        struct bpf_netfilter_opts opts = {
            .sz = sizeof(opts),
            .pf = NFPROTO_IPV4,
            .hooknum = NF_INET_LOCAL_OUT,
            .priority = -128,
        };
        auto* nf_link = bpf_program__attach_netfilter(prog, &opts);
        if (libbpf_get_error(nf_link) != 0) {
            // Changed: attach netfilter hook failed
            std::println("Failed to attach netfilter hook");
            return std::unexpected { ModuleError::NETFILTER_HOOK_ATTACH_FAILED };
        }
        return {};
    }

    std::expected<void, ModuleError> init_ring_buffer() {
        auto* map = bpf_object__find_map_by_name(obj_, "ringbuf");
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
