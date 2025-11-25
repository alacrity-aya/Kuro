#include <bpf/libbpf.h>
#include <bpf/libbpf_legacy.h>
#include <cerrno>
#include <cstring>
#include <modules/ip.hpp>
#include <net/if.h>
#include <tc_ip.skel.h>
#include <utils/parser.hpp>

namespace {

module::IpModule::IpKey to_bpf_key(const module::IpModule::IpRuleConfig& cfg) {
    module::IpModule::IpKey key {};
    key.ip = ::htonl(cfg.ip);
    key.port = ::htons(cfg.port);
    key.proto = cfg.proto;
    key.dir = cfg.gress;
    return key;
}

module::IpModule::IpValue to_bpf_value(const module::IpModule::IpRuleConfig& cfg) {
    module::IpModule::IpValue val {};
    val.rate_bps = cfg.rate_bps;
    val.time_scale = cfg.time_scale;
    val.tokens = cfg.rate_bps;
    val.last_ns = 0;
    val.lock = 0;
    return val;
}

template<typename T>
std::optional<T> opt(const toml::table& t, const std::string& k) {
    if (auto v = t[k].value<T>())
        return v;
    return std::nullopt;
}

template<typename T>
struct FieldPair {
    const std::optional<T>& rule;
    const std::optional<T>& base;
};

template<typename T>
std::expected<T, error::Error> get_field(FieldPair<T> pair) {
    const auto& [rule_v, base_v] = pair;
    if (rule_v)
        return *rule_v;
    if (base_v)
        return *base_v;

    return std::unexpected { error::Error { error::ErrorCode::PARSING_CONFIG_FAILED } };
}

}; // namespace

namespace module {

void IpModule::init() {
    this->cpus = libbpf_num_possible_cpus();
    constexpr size_t value_size = sizeof(FlowCounter);
    constexpr size_t rounded_value_size = (value_size + 7) & ~7;
    this->map_buffer.resize(rounded_value_size * this->cpus);
}

Result IpModule::load() {
    this->init();

    Result ret {};

    return ret

        .and_then([this]() -> Result {
            this->ifindex = static_cast<int32_t>(if_nametoindex(this->iface_name.c_str()));
            if (this->ifindex == 0) {
                return std::unexpected { Error {
                    ErrorCode::ATTACH_BPF_FAILED,
                    std::format(
                        "Interface '{}' not found or invalid. errno: {}",
                        this->iface_name,
                        strerror(errno)
                    ) } };
            }
            return {};
        })

        .and_then([this]() -> Result {
            if (this->configs.empty())
                return std::unexpected { Error { ErrorCode::EMPTY_RULE } };
            return {};
        })

        .and_then([this]() -> Result {
            if (this->skel = tc_ip__open_and_load(); this->skel == nullptr) {
                return std::unexpected { Error { ErrorCode::OPEN_AND_LOAD_BPF_FAILED } };
            }
            return {};
        })

        // update rules
        .and_then([this]() -> Result {
            if (this->skel->maps.ip_rules == nullptr) {
                return std::unexpected { Error { ErrorCode::FAILED_TO_FIND_MAP } };
            }

            for (const auto& cfg: this->configs) {
                IpKey key = to_bpf_key(cfg);
                IpValue value = to_bpf_value(cfg);

                if (bpf_map__update_elem(
                        this->skel->maps.ip_rules,
                        &key,
                        sizeof(key),
                        &value,
                        sizeof(value),
                        0
                    )
                    < 0)
                {
                    logger::error(
                        "Failed to update rule for IP: {}, Port: {}",
                        utils::ip_to_string(cfg.ip),
                        cfg.port
                    );
                    return std::unexpected { Error { ErrorCode::FAILED_TO_UPDATE_MAP } };
                }
            }
            logger::info("Loaded {} IP rules into BPF map", this->configs.size());
            return {};
        })

        //create hook
        .and_then([this]() -> Result {
            /* The hook (i.e. qdisc) may already exists because:
	        *   1. it is created by other processes or users
	        *   2. or since we are attaching to the TC ingress ONLY,
	        *      bpf_tc_hook_destroy does NOT really remove the qdisc,
	        *      there may be an egress filter on the qdisc
	        */

            // Ingress
            memset(&this->hook_ingress, 0, sizeof(this->hook_ingress));
            this->hook_ingress.sz = sizeof(this->hook_ingress);
            this->hook_ingress.ifindex = this->ifindex;
            this->hook_ingress.attach_point = BPF_TC_INGRESS;

            if (auto err = bpf_tc_hook_create(&this->hook_ingress); err && err != -EEXIST) {
                return std::unexpected { Error { ErrorCode::FAILED_TO_CREATE_TC_HOOK } };
            }

            struct bpf_tc_opts opts_ing = {};
            memset(&opts_ing, 0, sizeof(opts_ing));
            opts_ing.sz = sizeof(opts_ing);
            opts_ing.prog_fd = bpf_program__fd(this->skel->progs.ip_ingress);

            if (bpf_tc_attach(&this->hook_ingress, &opts_ing) != 0) {
                this->unload();
                return std::unexpected { Error { ErrorCode::ATTACH_BPF_FAILED,
                                                 "Failed to attach TC Ingress" } };
            }

            // Egress
            memset(&this->hook_egress, 0, sizeof(this->hook_egress));
            this->hook_egress.sz = sizeof(this->hook_egress);
            this->hook_egress.ifindex = this->ifindex;
            this->hook_egress.attach_point = BPF_TC_EGRESS;

            if (auto err = bpf_tc_hook_create(&this->hook_egress); err && err != -EEXIST) {
                return std::unexpected { Error { ErrorCode::FAILED_TO_CREATE_TC_HOOK } };
            }

            struct bpf_tc_opts opts_eg = {};
            memset(&opts_eg, 0, sizeof(opts_eg));
            opts_eg.sz = sizeof(opts_eg);
            opts_eg.prog_fd = bpf_program__fd(this->skel->progs.ip_egress);

            if (bpf_tc_attach(&this->hook_egress, &opts_eg) != 0) {
                this->unload();
                return std::unexpected { Error { ErrorCode::ATTACH_BPF_FAILED,
                                                 "Failed to attach TC Egress" } };
            }

            logger::info("IpModule attached to interface index {}", this->ifindex);
            return {};
        })

        //handle error
        .or_else([this](const auto&& err) -> Result {
            this->unload();
            return std::unexpected { err };
        });

    return ret;
}

// ---------------------------------------------------------
// main parser (Base ⊕ Rule merge, rule overrides base)
// ---------------------------------------------------------
Result IpModule::parse_config(const toml::table* table) {
    if (table == nullptr) {
        logger::error("config == nullptr");
        return std::unexpected { Error { ErrorCode::EMPTY_CONFIG_NODE } };
    }

    // Helper for generating consistent configuration errors
    auto config_error = [&](const std::string& msg,
                            std::source_location loc = std::source_location::current()) {
        logger::error("Configuration error: {}", msg);
        return std::unexpected { Error { ErrorCode::PARSING_CONFIG_FAILED, msg, loc } };
    };

    if (const auto* iface_node = table->get("interface"); iface_node) {
        if (auto val = iface_node->value<std::string>()) {
            this->iface_name = *val;
        } else {
            return config_error("'interface' must be a string (e.g., \"eth0\")");
        }
    }

    // 1. Extract Base Configs (Strategy)
    // These are optional at this stage; they are only required if the specific rule doesn't provide them.
    auto base_proto_str = opt<std::string>(*table, "proto");
    auto base_gress_str = opt<std::string>(*table, "gress");
    auto base_rate_str = opt<std::string>(*table, "rate_bps");
    auto base_ts_str = opt<std::string>(*table, "time_scale");

    // These are usually in the rules, but we allow base defaults
    auto base_ip_str = opt<std::string>(*table, "ip");
    auto base_port = opt<uint16_t>(*table, "port");

    // 2. Get Rules Array
    const auto* node = table->get("rules");
    if (node == nullptr) {
        return std::unexpected { Error { ErrorCode::PARSE_MISSING_REQUIRED_FIELD,
                                         ": rules array missing" } };
    }
    if (!node->is_array()) {
        return config_error("'rules' must be an array");
    }

    const auto* rules = node->as_array();

    // Clear existing configs before parsing new ones
    this->configs.clear();
    this->configs.reserve(rules->size());

    // 3. Iterate and Merge
    for (size_t i = 0; i < rules->size(); ++i) {
        const auto* rule_node = rules->get(i);
        if (!rule_node->is_table()) {
            return config_error(std::format("Rule index {} is not a table", i));
        }
        const auto& r = *rule_node->as_table();

        // --- Merge Helper ---
        // Resolves the value: Rule > Base > Error if both missing
        auto resolve = [&](const std::optional<std::string>& rule_val,
                           const std::optional<std::string>& base_val,
                           const std::string& field_name) -> std::expected<std::string, Error> {
            if (rule_val && !rule_val->empty())
                return *rule_val;
            if (base_val && !base_val->empty())
                return *base_val;
            return std::unexpected { Error {
                ErrorCode::PARSE_MISSING_REQUIRED_FIELD,
                std::format(": {} (at rule index {})", field_name, i) } };
        };

        IpRuleConfig cfg {};

        // A. IP (Required)
        auto ip_res = resolve(opt<std::string>(r, "ip"), base_ip_str, "ip");
        if (!ip_res)
            return std::unexpected { ip_res.error() };

        auto parsed_ip = utils::parse_ip(*ip_res);
        if (!parsed_ip)
            return std::unexpected { Error { parsed_ip.error(), std::format("ip={}", *ip_res) } };
        cfg.ip = *parsed_ip;

        // B. Port (Required)
        // Special handling for int type
        auto r_port = opt<uint16_t>(r, "port");
        if (r_port)
            cfg.port = *r_port;
        else if (base_port)
            cfg.port = *base_port;
        else
            return config_error(std::format("Missing required field: port (at rule index {})", i));

        // C. Protocol (Required)
        auto proto_res = resolve(opt<std::string>(r, "proto"), base_proto_str, "proto");
        if (!proto_res)
            return std::unexpected { proto_res.error() };

        auto parsed_proto = utils::parse_protocol(*proto_res);
        if (!parsed_proto)
            return std::unexpected { Error { parsed_proto.error(),
                                             std::format("proto={}", *proto_res) } };
        cfg.proto = *parsed_proto;

        // D. Gress (Required)
        auto gress_res = resolve(opt<std::string>(r, "gress"), base_gress_str, "gress");
        if (!gress_res)
            return std::unexpected { gress_res.error() };

        auto parsed_gress = utils::parse_gress(*gress_res);
        if (!parsed_gress)
            return std::unexpected { Error { parsed_gress.error(),
                                             std::format("gress={}", *gress_res) } };
        cfg.gress = *parsed_gress;

        // E. Rate BPS (Required)
        auto rate_res = resolve(opt<std::string>(r, "rate_bps"), base_rate_str, "rate_bps");
        if (!rate_res)
            return std::unexpected { rate_res.error() };

        auto parsed_rate = utils::parse_rate_bytes_ps(*rate_res);
        if (!parsed_rate)
            return std::unexpected { Error { parsed_rate.error(),
                                             std::format("rate_bps={}", *rate_res) } };
        cfg.rate_bps = *parsed_rate;

        // F. Time Scale (Optional, default 0)
        // We don't use 'resolve' here because it's not strictly required to fail if missing
        std::string ts_str;
        if (auto v = opt<std::string>(r, "time_scale"); v)
            ts_str = *v;
        else if (base_ts_str)
            ts_str = *base_ts_str;

        if (!ts_str.empty()) {
            auto parsed_ts = utils::parse_time_scale(ts_str);
            if (!parsed_ts)
                return std::unexpected { Error { parsed_ts.error(),
                                                 std::format("time_scale={}", ts_str) } };
            cfg.time_scale = *parsed_ts;
        } else {
            cfg.time_scale = 0;
        }

        // Add to configs
        this->configs.push_back(cfg);

        logger::debug(
            "Parsed rule #{}: ip={}, port={}, proto={}, gress={}, rate={}, ts={}",
            i,
            *ip_res,
            cfg.port,
            *proto_res,
            *gress_res,
            *rate_res,
            cfg.time_scale
        );
    }

    logger::info("Successfully parsed {} IP rules", this->configs.size());
    return {};
}

void IpModule::unload() {
    if (this->hook_ingress.ifindex > 0) {
        int err = bpf_tc_hook_destroy(&this->hook_ingress);
        if (err < 0 && err != -ENOENT) {
            logger::warn("Failed to destroy ingress hook: {}", strerror(-err));
        }
    }

    if (this->hook_egress.ifindex > 0) {
        int err = bpf_tc_hook_destroy(&this->hook_egress);
        if (err < 0 && err != -ENOENT) {
            logger::warn("Failed to destroy egress hook: {}", strerror(-err));
        }
    }

    if (this->skel != nullptr) {
        tc_ip__destroy(this->skel);
        this->skel = nullptr;
    }

    this->configs.clear();
}

std::string IpModule::type() {
    return "IpModule";
}

FlowRate IpModule::calc_rate() {
    if (this->skel == nullptr)
        return {};

    uint32_t key = 0;

    if (bpf_map__lookup_elem(
            this->skel->maps.ip_stats,
            &key,
            sizeof(key),
            this->map_buffer.data(),
            this->map_buffer.size(),
            0
        )
        != 0)
    {
        logger::warn("Failed to lookup ip_stats map");
        return {};
    }

    FlowCounter current_total {};
    constexpr size_t value_size = sizeof(FlowCounter);
    constexpr size_t step = (value_size + 7) & ~7;

    for (int i = 0; i < this->cpus; i++) {
        auto* cpu_stats = reinterpret_cast<FlowCounter*>(this->map_buffer.data() + (i * step));
        current_total.accepted_bytes += cpu_stats->accepted_bytes;
        current_total.dropped_bytes += cpu_stats->dropped_bytes;
        current_total.accepted_packets += cpu_stats->accepted_packets;
        current_total.dropped_packets += cpu_stats->dropped_packets;
    }

    auto now = std::chrono::steady_clock::now();

    if (!this->rate_initialized) [[unlikely]] {
        this->rate_initialized = true;
        this->last_time = now;
        this->last_flow = current_total;
        return FlowRate {};
    }

    const double dt = std::chrono::duration<double>(now - this->last_time).count();
    const double safe_dt = (dt > 1e-9) ? dt : 1e-9; // avoid being divided by zero

    uint64_t d_acc_bytes = current_total.accepted_bytes - this->last_flow.accepted_bytes;
    uint64_t d_drop_bytes = current_total.dropped_bytes - this->last_flow.dropped_bytes;
    uint64_t d_acc_pkts = current_total.accepted_packets - this->last_flow.accepted_packets;
    uint64_t d_drop_pkts = current_total.dropped_packets - this->last_flow.dropped_packets;

    this->last_flow = current_total;
    this->last_time = now;

    return FlowRate {
        .accepted_bytes_rate = static_cast<double>(d_acc_bytes) / safe_dt,
        .dropped_bytes_rate = static_cast<double>(d_drop_bytes) / safe_dt,
        .accepted_packets_rate = static_cast<double>(d_acc_pkts) / safe_dt,
        .dropped_packets_rate = static_cast<double>(d_drop_pkts) / safe_dt,
    };
}

} // namespace module
