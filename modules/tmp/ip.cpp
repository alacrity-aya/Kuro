#include "modules/ip.hpp"
#include <bpf/bpf.h> // bpf_map_update_elem
#include <bpf/libbpf.h>
#include <source_location>
#include <unistd.h>
#include <utils/parser.hpp>

namespace module {

IpModule::IpModule() {
    // 构造时可以做一些基础初始化，或者留给 load
}

IpModule::~IpModule() {
    this->unload();
}

std::string IpModule::type() {
    return "IpModule";
}

void IpModule::init_buffers() {
    // 初始化 percpu map 读取缓冲区
    // FlowCounter 需要按 8 字节对齐
    constexpr uint64_t elem_sz = ((sizeof(FlowCounter) + 7) & ~7);
    this->raw_stats_buffer.resize(elem_sz * this->cpus);
}

ModuleResult IpModule::parse_config(const toml::table* config) {
    if (config == nullptr) {
        logger.error("config = nullptr");
        return std::unexpected { ModuleError { ErrorCode::EMPTY_CONFIG_NODE } };
    }

    // 1. 解析 Interface (默认为 lo)
    if (auto node = config->get("interface"); node) {
        this->interface_name = node->value_or<std::string>("lo");
    }

    // 2. 解析 Rules 数组
    const auto* rules_arr = config->get_as<toml::array>("rules");
    if (rules_arr == nullptr) {
        logger.warn("IpModule: No rules found");
        return {};
    }

    std::source_location loc;

    // 遍历所有规则配置
    for (const auto& node: *rules_arr) {
        const auto* tbl = node.as_table();
        if (!tbl)
            continue;

        try {
            IpRuleConfig cfg {};

            // IP
            auto ip_str = tbl->get("ip")->value_or<std::string>("");
            auto ip_opt = utils::parse_ip(ip_str);
            if (!ip_opt) {
                logger.warn("Invalid IP: {}", ip_str);
                continue;
            }
            cfg.ip = htonl(*ip_opt); // 转为网络字节序

            // Port
            cfg.port = htons(tbl->get("port")->value_or<uint16_t>(0));

            // Protocol
            auto proto_str = tbl->get("protocol")->value_or<std::string>("");
            auto proto_opt = utils::parse_protocol(proto_str);
            cfg.proto = proto_opt.value_or(0);

            // Gress (Direction)
            auto gress_str = tbl->get("gress")->value_or<std::string>("");
            auto gress_opt = utils::parse_gress(gress_str);
            if (!gress_opt) {
                logger.warn("Invalid gress: {}", gress_str);
                continue;
            }
            cfg.dir = *gress_opt;

            // Rate
            auto rate_str = tbl->get("rate_bps")->value_or<std::string>("0");
            cfg.rate_bps = utils::parse_rate_bps(rate_str).value_or(0);

            // Time Scale
            auto time_str = tbl->get("time_scale")->value_or<std::string>("100ms");
            cfg.time_scale = utils::parse_time_scale(time_str).value_or(0);

            this->configs.push_back(cfg);

            logger.info(
                "Parsed IP Rule: if={}, ip={}, port={}, dir={}, rate={}",
                interface_name,
                ip_str,
                ntohs(cfg.port),
                cfg.dir,
                cfg.rate_bps
            );

        } catch (const std::exception& e) {
            return std::unexpected { ModuleError { ErrorCode::PARSING_CONFIG_FAILED, e.what() } };
        }
    }

    return {};
}

ModuleResult IpModule::load() {
    this->init_buffers();

    // 1. Open and Load BPF Skeleton
    this->skel = tc_ip__open();
    if (!this->skel)
        return std::unexpected { ModuleError { ErrorCode::OPEN_BPF_FAILED } };

    if (tc_ip__load(this->skel) != 0) {
        tc_ip__destroy(this->skel);
        this->skel = nullptr;
        return std::unexpected { ModuleError { ErrorCode::LOAD_BPF_FAILED } };
    }

    // 2. 获取网卡索引
    this->if_index = if_nametoindex(this->interface_name.c_str());
    if (this->if_index == 0) {
        logger.error("Invalid interface name: {}", this->interface_name);
        return std::unexpected { ModuleError { ErrorCode::Custom, "Invalid interface" } };
    }

    // 3. 挂载 TC Hooks (使用 libbpf TC API)

    // --- Ingress Hook ---
    memset(&this->hook_ingress, 0, sizeof(this->hook_ingress));
    this->hook_ingress.sz = sizeof(struct bpf_tc_hook);
    this->hook_ingress.ifindex = this->if_index;
    this->hook_ingress.attach_point = BPF_TC_INGRESS;

    // 创建 clsact qdisc (如果已存在则忽略 EEXIST)
    int err = bpf_tc_hook_create(&this->hook_ingress);
    if (err && err != -EEXIST) {
        return std::unexpected { ModuleError { ErrorCode::ATTACH_BPF_FAILED,
                                               "Failed to create TC ingress hook" } };
    }

    struct bpf_tc_opts opts_in {};
    memset(&opts_in, 0, sizeof(opts_in));
    opts_in.sz = sizeof(opts_in);
    opts_in.prog_fd = bpf_program__fd(this->skel->progs.ip_ingress);

    if (bpf_tc_attach(&this->hook_ingress, &opts_in) != 0) {
        return std::unexpected { ModuleError { ErrorCode::ATTACH_BPF_FAILED,
                                               "Failed to attach Ingress prog" } };
    }
    this->ingress_attached = true;

    // --- Egress Hook ---
    memset(&this->hook_egress, 0, sizeof(this->hook_egress));
    this->hook_egress.sz = sizeof(struct bpf_tc_hook);
    this->hook_egress.ifindex = this->if_index;
    this->hook_egress.attach_point = BPF_TC_EGRESS;

    // Hook create (通常 Ingress 创建后 clsact 已存在，这里是防御性调用)
    bpf_tc_hook_create(&this->hook_egress);

    struct bpf_tc_opts opts_out {};
    memset(&opts_out, 0, sizeof(opts_out));
    opts_out.sz = sizeof(opts_out);
    opts_out.prog_fd = bpf_program__fd(this->skel->progs.ip_egress);

    if (bpf_tc_attach(&this->hook_egress, &opts_out) != 0) {
        return std::unexpected { ModuleError { ErrorCode::ATTACH_BPF_FAILED,
                                               "Failed to attach Egress prog" } };
    }
    this->egress_attached = true;

    // 4. 更新 MAP 规则
    int map_fd = bpf_map__fd(this->skel->maps.ip_rules);
    if (map_fd < 0)
        return std::unexpected { ModuleError { ErrorCode::FAILED_TO_FIND_MAP } };

    for (const auto& cfg: this->configs) {
        IpKey key { .ip = cfg.ip, .port = cfg.port, .proto = cfg.proto, .dir = cfg.dir };

        IpValue val { .rate_bps = cfg.rate_bps,
                      .time_scale = cfg.time_scale,
                      .tokens = 0, // Init state
                      .last_ns = 0, // Init state
                      .lock = 0 };

        if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY) != 0) {
            logger.error("Failed to update map for IP rule: ip={:x}", ntohl(cfg.ip));
            return std::unexpected { ModuleError { ErrorCode::FAILED_TO_UPDATE_MAP } };
        }
    }

    logger.info("IpModule loaded successfully on interface {}", interface_name);
    return {};
}

void IpModule::unload() {
    // 1. Detach TC programs
    if (this->ingress_attached) {
        struct bpf_tc_opts opts {};
        opts.sz = sizeof(opts);
        opts.prog_fd = bpf_program__fd(this->skel->progs.ip_ingress);
        opts.flags = 0;
        opts.prog_id = 0;
        bpf_tc_detach(&this->hook_ingress, &opts);
        this->ingress_attached = false;
    }

    if (this->egress_attached) {
        struct bpf_tc_opts opts {};
        opts.sz = sizeof(opts);
        opts.prog_fd = bpf_program__fd(this->skel->progs.ip_egress);
        opts.flags = 0;
        opts.prog_id = 0;
        bpf_tc_detach(&this->hook_egress, &opts);
        this->egress_attached = false;
    }

    // 注意：通常我们不销毁 qdisc (hook_destroy)，
    // 因为这可能会移除该网卡上所有其他的 TC 程序（clsact 是共享的）。

    // 2. Destroy Skeleton
    if (this->skel) {
        tc_ip__destroy(this->skel);
        this->skel = nullptr;
    }

    logger.info("IpModule unloaded");
}

FlowRate IpModule::calc_rate() {
    if (!this->skel)
        return FlowRate {};

    // 读取 Map: ip_stats (PERCPU_ARRAY, Key=0)
    // 注意：目前的 BPF 逻辑是所有 IP 规则共享一个全局统计 Key=0。
    // 如果你需要分 IP 统计，BPF 端和这里都需要修改为 Hash Map 或根据 Key 遍历。
    const uint32_t key = 0;
    int map_fd = bpf_map__fd(this->skel->maps.ip_stats);

    if (bpf_map__lookup_elem(map_fd, &key, this->raw_stats_buffer.data()) != 0) {
        logger.warn(
            "{}: failed to lookup ip_stats map",
            std::source_location::current().function_name()
        );
        return FlowRate {};
    }

    // 聚合所有 CPU 的统计数据
    FlowCounter total {};
    constexpr uint64_t elem_sz = ((sizeof(FlowCounter) + 7) & ~7);

    for (int i = 0; i < this->cpus; i++) {
        const auto* pcpu =
            reinterpret_cast<const FlowCounter*>(this->raw_stats_buffer.data() + (i * elem_sz));
        total.accepted_bytes += pcpu->accepted_bytes;
        total.dropped_bytes += pcpu->dropped_bytes;
        total.accepted_packets += pcpu->accepted_packets;
        total.dropped_packets += pcpu->dropped_packets;
    }

    auto now = std::chrono::steady_clock::now();

    // 第一次调用初始化
    if (!this->rate_initialized) [[unlikely]] {
        this->rate_initialized = true;
        this->last_time = now;
        this->last_flow = total;
        return FlowRate {};
    }

    // 计算速率
    const double dt = std::chrono::duration<double>(now - this->last_time).count();
    const double safe_dt = (dt > 1e-9) ? dt : 1e-9;

    uint64_t delta_acc_bytes = total.accepted_bytes - this->last_flow.accepted_bytes;
    uint64_t delta_drop_bytes = total.dropped_bytes - this->last_flow.dropped_bytes;
    uint64_t delta_acc_pkts = total.accepted_packets - this->last_flow.accepted_packets;
    uint64_t delta_drop_pkts = total.dropped_packets - this->last_flow.dropped_packets;

    // 更新状态
    this->last_flow = total;
    this->last_time = now;

    return FlowRate {
        .accepted_bytes_rate = static_cast<double>(delta_acc_bytes) / safe_dt,
        .dropped_bytes_rate = static_cast<double>(delta_drop_bytes) / safe_dt,
        .accepted_packets_rate = static_cast<double>(delta_acc_pkts) / safe_dt,
        .dropped_packets_rate = static_cast<double>(delta_drop_pkts) / safe_dt,
    };
}

} // namespace module
