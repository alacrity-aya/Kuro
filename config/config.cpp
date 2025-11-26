#include <config/config.hpp>
#include <iostream>

namespace {

logger::LogPriority parse_log_level(const std::string& s) {
    using L = logger::LogPriority;
    std::string lv = s;
    std::ranges::transform(lv, lv.begin(), ::tolower);

    if (lv == "trace")
        return L::TRACE;
    if (lv == "debug")
        return L::DEBUG;
    if (lv == "info")
        return L::INFO;
    if (lv == "warn")
        return L::WARN;
    if (lv == "error")
        return L::ERROR;
    if (lv == "fatal")
        return L::FATAL;

    logger::warn("failed to parse_log_level: s = {}, fallback to LogPriority::INFO", s);
    return L::INFO;
}

bool is_valid_ip_port(const std::string& input) {
    const std::string ipv4_segment = "(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])";
    const std::string port_segment =
        "([1-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-3][0-5])"; // 1-65535

    const std::regex pattern(
        "^" + ipv4_segment + "\\." + ipv4_segment + "\\." + ipv4_segment + "\\." + ipv4_segment
        + // IP
        ":" + port_segment + "$"
    ); // Port

    return std::regex_match(input, pattern);
}
} // namespace
namespace config {

bool Config::load(std::string_view path) {
    try {
        auto result = toml::parse_file(path);
        if (!result) {
            std::cerr << "Parsing failed:\n" << result.error() << "\n";
            return false;
        }
        const auto& tbl = result.table();

        // --- log.level ---
        if (auto v = tbl["log"]["level"].value<std::string>()) {
            this->log_level = parse_log_level(*v);
        }

        // -- rpc.address --
        if (auto addr = tbl["rpc"]["address"].value<std::string>()) {
            if (!is_valid_ip_port(*addr)) {
                return false;
            }
            this->rpc_server_addr = *addr;
        }

        loaded = true;
        return true;
    } catch (const std::exception& e) {
        logger::error("loading config failed, err: {}", e.what());
        return false;
    }
}

} // namespace config
