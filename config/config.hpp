#pragma once

#include <logger/logger.hpp>
#include <string>
#include <string_view>
#include <toml++/toml.h>
#include <utils/singleton.hpp>

namespace config {

class Config: public Singleton<Config> {
public:
    bool load(std::string_view path);

    [[nodiscard]] bool is_loaded() const noexcept {
        return this->loaded;
    }

    [[nodiscard]] logger::LogPriority get_log_level() const noexcept {
        return this->log_level;
    }

    [[nodiscard]] std::string get_rpc_server_address() const noexcept {
        return this->rpc_server_addr;
    }

    [[nodiscard]] bool is_enable_thread_id() const noexcept {
        return this->enable_thread_id;
    }

    [[nodiscard]] bool is_enable_time_recording() const noexcept {
        return this->enable_time_recording;
    }

    [[nodiscard]] logger::LogMode get_log_mode() const noexcept {
        return this->log_mode;
    }

private:
    friend class Singleton<Config>;

    Config() = default;

    bool loaded = false;
    logger::LogPriority log_level = logger::LogPriority::INFO;
    std::string rpc_server_addr;
    bool enable_time_recording { true };
    bool enable_thread_id { true };

    logger::LogMode log_mode { logger::LogMode::SYNC };
};

inline logger::LogPriority log_level() {
    return Config::instance().get_log_level();
}

inline std::string rpc_server_addr() {
    return Config::instance().get_rpc_server_address();
}

inline bool is_enable_thread_id() {
    return Config::instance().is_enable_thread_id();
}

inline bool is_enable_time_recording() {
    return Config::instance().is_enable_time_recording();
}

inline logger::LogMode log_mode() {
    return Config::instance().get_log_mode();
}

} // namespace config
