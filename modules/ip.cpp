#include <modules/ip.hpp>
#include <tc_ip.skel.h>
#include <utils/parser.hpp>

namespace {

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

Result IpModule::load() {
    logger.trace("{} is called ", __PRETTY_FUNCTION__);
    return {};
}

// ---------------------------------------------------------
// main parser (Base ⊕ Rule merge, rule overrides base)
// ---------------------------------------------------------
Result IpModule::parse_config(const toml::table* table) {
    if (table == nullptr) {
        logger.error("config == nullptr");
        return std::unexpected { Error { ErrorCode::EMPTY_CONFIG_NODE } };
    }

    // Helper for generating consistent configuration errors
    auto config_error = [&](const std::string& msg,
                            std::source_location loc = std::source_location::current()) {
        logger.error("Configuration error: {}", msg);
        return std::unexpected { Error { ErrorCode::PARSING_CONFIG_FAILED, msg, loc } };
    };

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

        auto parsed_rate = utils::parse_rate_bps(*rate_res);
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

        logger.debug(
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

    logger.info("Successfully parsed {} IP rules", this->configs.size());
    return {};
}

void IpModule::unload() {
    logger.trace("{} is called ", __PRETTY_FUNCTION__);
}

std::string IpModule::type() {
    return "IpModule";
}

FlowRate IpModule::calc_rate() {
    logger.trace("{} is called ", __PRETTY_FUNCTION__);
    return {};
}

} // namespace module
