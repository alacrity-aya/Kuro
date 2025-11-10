#pragma once
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/libbpf_legacy.h>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <getopt.h>
#include <iostream>
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

struct ProcessRule {
    uint32_t target_pid;
    uint64_t rate_bps;
    uint8_t gress;
    uint32_t time_scale;
};

struct ProcInfo {
    __u32 pid;
    char comm[16];
};

struct MessageGet {
    __u64 instance_rate_bps;
    __u64 rate_bps;
    __u64 peak_rate_bps;
    __u64 smoothed_rate_bps;
    struct ProcInfo proc;
    __u64 timestamp;
};

namespace {

    struct bpf_object* obj = nullptr;
    struct bpf_link* recvmsg_kprobe = nullptr;
    struct bpf_link* sendmsg_kprobe = nullptr;
    int nf_fd_ingress = -1;
    int nf_fd_egress = -1;
    struct ring_buffer* rb = nullptr;
} // namespace

int get_rule() {
    struct ProcessRule rule = {};

    // process_module:
    //  process_rule:
    //    target_pid: 12284
    //    rate_bps: 1M
    //    gress: ingress
    //    time_scale: 1s
    //

    rule.target_pid = 21573;
    rule.rate_bps = static_cast<uint64_t>(1024 * 1024 * 100);
    rule.gress = 1;
    rule.time_scale = 10;

    std::cout << "PID: " << rule.target_pid << "\n";
    std::cout << "Rate: " << rule.rate_bps << " bps\n";
    std::cout << "Gress: " << rule.gress << "\n";
    std::cout << "Time Scale: " << rule.time_scale << " sec\n";

    struct bpf_map* map = bpf_object__find_map_by_name(obj, "process_rules");
    if (!map) {
        std::cout << "NO1" << "\n";
        return false;
    }

    uint32_t key = 0;
    int err = bpf_map__update_elem(map, &key, sizeof(key), &rule, sizeof(rule), BPF_ANY);
    if (err) {
        std::cout << "NO3" << "\n";
        return false;
    }
    return true;
}

std::string get_local_ip_address() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return "127.0.0.1";
    }

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("8.8.8.8");
    addr.sin_port = htons(53);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return "127.0.0.1";
    }

    socklen_t len = sizeof(addr);
    if (getsockname(sock, (struct sockaddr*)&addr, &len) < 0) {
        close(sock);
        return "127.0.0.1";
    }

    close(sock);

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr.sin_addr, ip_str, INET_ADDRSTRLEN);

    return std::string(ip_str);
}

static bool setup_local_ip_map() {
    struct bpf_map* map = bpf_object__find_map_by_name(obj, "local_ip_map");
    if (!map) {
        std::cerr << "No local_ip_map" << std::endl;
        return false;
    }

    std::string local_ip = get_local_ip_address();
    std::cout << "local IP: " << local_ip << std::endl;

    uint32_t key = 0;
    uint32_t ip_addr = inet_addr(local_ip.c_str());

    int err = bpf_map__update_elem(map, &key, sizeof(key), &ip_addr, sizeof(ip_addr), BPF_ANY);
    if (err) {
        std::cerr << "error" << err << std::endl;
        return false;
    }

    std::cout << "set local ip to BPF map" << std::endl;
    return true;
}

inline std::string format_elapsed_ns(uint64_t ns_since_boot) {
    // 转成毫秒
    uint64_t total_ms = ns_since_boot / 1'000'000ULL;
    uint64_t hours = total_ms / 3'600'000ULL;
    uint64_t minutes = (total_ms % 3'600'000ULL) / 60'000ULL;
    uint64_t seconds = (total_ms % 60'000ULL) / 1'000ULL;
    uint64_t millis = total_ms % 1'000ULL;

    std::ostringstream oss;
    oss << std::setfill('0') << std::setw(2) << hours << ':' << std::setw(2) << minutes << ':'
        << std::setw(2) << seconds << '.' << std::setw(3) << millis;
    return oss.str();
}

static int handle_event(void* ctx, void* data, size_t data_sz) {
    if (data_sz != sizeof(MessageGet)) {
        std::cerr << "数据大小不匹配: " << data_sz << " (期望 " << sizeof(MessageGet) << ")\n";
        return 0;
    }

    auto* e = static_cast<const MessageGet*>(data);
    std::cout << std::fixed << std::setprecision(2) << "=== process_traffic ===\n"
              << " instant_rate_bps : " << e->instance_rate_bps / 1024.0 / 1024.0 << " MB/s\n"
              << " rate_bps         : " << e->rate_bps / 1024.0 / 1024.0 << " MB/s\n"
              << " peak_rate_bps    : " << e->peak_rate_bps / 1024.0 / 1024.0 << " MB/s\n"
              << " smoothed_rate_bps: " << e->smoothed_rate_bps / 1024.0 / 1024.0 << " MB/s\n"
              << " timestamp         : " << format_elapsed_ns(e->timestamp) << "\n"
              << "=====================\n";

    return 0;
}

static int load_netfilter_module() {
    if (getuid() != 0) {
        std::cerr << "[netfilter] 错误：需要 root 权限\n";
        return -1;
    }

    auto project_root = utils::find_project_root().value(); // TODO(alacrity): handle expection here
    auto tc_process_path = project_root / "bpf" / "build" / "tc_process.o";
    obj = bpf_object__open_file(tc_process_path.c_str(), nullptr);
    if (!obj || libbpf_get_error(obj)) {
        std::cerr << "[netfilter] 打开 BPF 对象失败\n";
        return -1;
    }
    if (bpf_object__load(obj)) {
        std::cerr << "[netfilter] 加载 BPF 对象失败\n";
        bpf_object__close(obj);
        obj = nullptr;
        return -1;
    }

    {
        auto prog = bpf_object__find_program_by_name(obj, "security_socket_recvmsg");
        if (prog)
            recvmsg_kprobe = bpf_program__attach_kprobe(prog, false, "security_socket_recvmsg");
        if (!recvmsg_kprobe) {
            std::cerr << "[netfilter] attach recvmsg kprobe 失败\n";
            goto error;
        }
    }

    {
        auto prog = bpf_object__find_program_by_name(obj, "security_socket_sendmsg");
        if (prog)
            sendmsg_kprobe = bpf_program__attach_kprobe(prog, false, "security_socket_sendmsg");
        if (!sendmsg_kprobe) {
            std::cerr << "[netfilter] attach sendmsg kprobe 失败\n";
            goto error;
        }
    }

    if (!setup_local_ip_map()) {
        std::cerr << "[netfilter] setup_local_ip_map 失败\n";
        goto error;
    }

    {
        auto prog = bpf_object__find_program_by_name(obj, "netfilter_hook");
        if (!prog) {
            std::cerr << "[netfilter] 找不到 netfilter_hook 程序\n";
            goto error;
        }
        __u32 prog_fd = bpf_program__fd(prog);
        struct bpf_netfilter_opts opts = {
            .sz = sizeof(opts),
            .pf = NFPROTO_IPV4,
            .hooknum = NF_INET_LOCAL_OUT,
            .priority = -128,
            // .flags = 0,
        };
        auto nf_link_egress = bpf_program__attach_netfilter(prog, &opts);
        if (libbpf_get_error(nf_link_egress)) {
            std::println("failed to attach netfilter!\n");
            nf_link_egress = nullptr;
            goto error;
        }

        get_rule();
    }

    std::cout << "[netfilter] 成功附加 kprobe 和 netfilter 钩子\n";

    {
        auto map = bpf_object__find_map_by_name(obj, "ringbuf");
        int map_fd = bpf_map__fd(map);
        rb = ring_buffer__new(map_fd, handle_event, nullptr, nullptr);
        if (!rb) {
            std::cerr << "[netfilter] 创建 ring buffer 失败\n";
            goto error;
        }
    }

    std::cout << "[netfilter] 模块加载完成，开始处理事件\n";
    return 0;

error:
    if (recvmsg_kprobe)
        bpf_link__destroy(recvmsg_kprobe);
    if (sendmsg_kprobe)
        bpf_link__destroy(sendmsg_kprobe);
    if (nf_fd_ingress >= 0)
        close(nf_fd_ingress);
    if (nf_fd_egress >= 0)
        close(nf_fd_egress);
    if (obj) {
        bpf_object__close(obj);
        obj = nullptr;
    }
    return -1;
}

static void unload_netfilter_module() {
    if (rb)
        ring_buffer__free(rb);
    if (recvmsg_kprobe)
        bpf_link__destroy(recvmsg_kprobe);
    if (sendmsg_kprobe)
        bpf_link__destroy(sendmsg_kprobe);
    if (nf_fd_ingress >= 0)
        close(nf_fd_ingress);
    if (nf_fd_egress >= 0)
        close(nf_fd_egress);
    if (obj) {
        bpf_object__close(obj);
        obj = nullptr;
    }
    std::cout << "[netfilter] 模块已卸载\n";
}

} // namespace process_module
