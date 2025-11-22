#include "utils/parser.hpp"
#include <modules/ip.hpp>

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
std::expected<T, error::ModuleError> get_field(FieldPair<T> pair) {
    const auto& [rule_v, base_v] = pair;
    if (rule_v)
        return *rule_v;
    if (base_v)
        return *base_v;

    return std::unexpected { error::ModuleError { error::ErrorCode::PARSING_CONFIG_FAILED } };
}

}; // namespace

namespace module {

ModuleResult IpModule::load() {
    logger.trace("{} is called ", __PRETTY_FUNCTION__);
    return {};
}

// ---------------------------------------------------------
// main parser (Base ⊕ Rule merge, rule overrides base)
// ---------------------------------------------------------
ModuleResult IpModule::parse_config(const toml::table* table) {
    if (table == nullptr) {
        return std::unexpected { ModuleError { ErrorCode::EMPTY_CONFIG_NODE } };
    }

    auto& configs = this->configs;

    auto base_proto = opt<std::string>(*table, "proto");
    auto base_gress = opt<std::string>(*table, "gress");
    auto base_rate = opt<std::string>(*table, "rate_bps");
    auto base_ts = opt<std::string>(*table, "time_scale");
    auto base_ip = opt<std::string>(*table, "ip");
    auto base_port = opt<uint16_t>(*table, "port");

    const auto* node = table->get("rules");
    if (node == nullptr || !node->is_array()) {
        return std::unexpected { ModuleError { ErrorCode::PARSING_CONFIG_FAILED } };
    }

    const auto* rules = node->as_array();

    for (const auto& rule: *rules) {
        const auto& r = *rule.as_table();

        auto r_proto = opt<std::string>(r, "proto");
        auto r_gress = opt<std::string>(r, "gress");
        auto r_rate = opt<std::string>(r, "rate_bps");
        auto r_ts = opt<std::string>(r, "time_scale");
        auto r_ip = opt<std::string>(r, "ip");
        auto r_port = opt<uint16_t>(r, "port");

        auto proto_e = get_field<std::string>({ .rule = r_proto, .base = base_proto });
        if (!proto_e)
            return std::unexpected { ModuleError { ErrorCode::PARSING_CONFIG_FAILED } };

        auto gress_e = get_field<std::string>({ .rule = r_gress, .base = base_gress });
        if (!gress_e)
            return std::unexpected { ModuleError { ErrorCode::PARSING_CONFIG_FAILED } };

        auto rate_e = get_field<std::string>({ .rule = r_rate, .base = base_rate });
        if (!rate_e)
            return std::unexpected { ModuleError { ErrorCode::PARSING_CONFIG_FAILED } };

        auto ts_e = get_field<std::string>({ .rule = r_ts, .base = base_ts });
        if (!ts_e)
            return std::unexpected { ModuleError { ErrorCode::PARSING_CONFIG_FAILED } };

        auto ip_s_e = get_field<std::string>({ .rule = r_ip, .base = base_ip });
        if (!ip_s_e)
            return std::unexpected { ModuleError { ErrorCode::PARSING_CONFIG_FAILED } };

        auto port_i_e = get_field<uint16_t>({ .rule = r_port, .base = base_port });
        if (!port_i_e)
            return std::unexpected { ModuleError { ErrorCode::PARSING_CONFIG_FAILED } };

        IpRuleConfig cfg;
    }

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
