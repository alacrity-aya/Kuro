#include "utils/parser.hpp"
#include <config/config.hpp>
#include <iostream>

namespace {

logger::LogPriority parse_log_level(const std::optional<std::string>& s) {
    using L = logger::LogPriority;
    if (!s.has_value()) {
        return L::INFO;
    }

    std::string lv = s.value();
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

    utils::panic("should be unreachable");
}

logger::LogMode parse_log_mode(const std::optional<std::string>& s) {
    using L = logger::LogMode;

    if (!s.has_value()) {
        return L::SYNC;
    }

    std::string lv = s.value();
    std::ranges::transform(lv, lv.begin(), ::tolower);

    if (lv == "async")
        return L::ASYNC;
    if (lv == "sync")
        return L::SYNC;

    return L::SYNC;
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

        // --- log ---

        this->log_level = parse_log_level(tbl["log"]["level"].value<std::string>());

        this->enable_time_recording =
            tbl["log"]["enable_time_recording"].value<bool>().value_or(true);

        this->enable_thread_id = tbl["log"]["enable_thread_id"].value<bool>().value_or(true);

        this->log_mode = parse_log_mode(tbl["log"]["mode"].value<std::string>());

        // -- rpc --
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
