#pragma once

#include "singleton.hpp"
#include <algorithm>
#include <array>
#include <expected>
#include <format>
#include <fstream>
#include <memory>
#include <mutex>
#include <print>
#include <string>
#include <string_view>
#include <vector>

namespace logger {

enum class LogPriority : uint8_t {
    TRACE = 0,
    DEBUG = 1,
    INFO = 2,
    WARN = 3,
    ERROR = 4,
    FATAL = 5,
};

class LogAppender {
public:
    using ptr = std::shared_ptr<LogAppender>;

    virtual ~LogAppender() = default;

    virtual void
    log(std::string_view message_priority_str,
        LogPriority /*message_priority*/,
        std::string message) = 0;

protected:
};

class FileAppender: public LogAppender {
public:
    using ptr = std::shared_ptr<FileAppender>;
    explicit FileAppender(std::string filename): _filename { std::move(filename) } {}

    std::expected<void, std::string> reopen_file() {
        if (_filestream.is_open()) {
            _filestream.close();
        }
        _filestream.open(_filename, std::ios::app | std::ios::out);
        if (!_filestream.is_open()) {
            return std::unexpected(std::format("{}: Fail to open file", __func__));
        }
        return {};
    }

    void
    log(std::string_view message_priority_str,
        LogPriority /*message_priority*/,
        std::string message) override {
        if (auto ret = log_impl(); ret.has_value()) {
            // TODO: add time stamp
            _filestream << message_priority_str << '\t' << message << '\n';
        } else {
            std::println(std::cerr, "{}", ret.error());
        }
    }

private:
    std::expected<void, std::string> log_impl() {
        if (_filestream.is_open()) {
            _filestream.close();
        }

        _filestream.open(_filename, std::ios::app | std::ios::out);

        if (!_filestream.is_open()) {
            return std::unexpected("FileAppender::log(): Fail to open file");
        }

        return {};
    }

    std::string _filename { "./log.txt" };
    std::ofstream _filestream;
};

class StdoutAppender: public LogAppender {
public:
    using ptr = std::shared_ptr<StdoutAppender>;

    void
    log(std::string_view message_priority_str,
        LogPriority /*message_priority*/,
        std::string message) override {
        std::println("{}{}", message_priority_str, message);
    }
};

class Logger: public Singleton<Logger> {
    friend class Singleton<Logger>;

public:
    using ptr = std::shared_ptr<Logger>;

public:
    Logger& enable_time_recording() {
        _enable_time_recording = true;
        return *this;
    }

    Logger& add_appender(const LogAppender::ptr& appender) {
        _apprenders.emplace_back(appender);
        return *this;
    }

    Logger& set_priority(LogPriority new_priority) {
        _priority = new_priority;
        return *this;
    }

#define XX(func, arg, priority) \
    template<class... Args> \
    void func(std::string_view fmt, Args&&... args) { \
        if (_priority <= LogPriority::priority) { \
            auto msg = std::vformat(fmt, std::make_format_args(args...)); \
            log(#arg, LogPriority::priority, std::move(msg)); \
        } \
    }

    XX(trace, [Trace]\t, TRACE)
    XX(debug, [Debug]\t, DEBUG)
    XX(info, [Info]\t, INFO)
    XX(warn, [Warn]\t, WARN)
    XX(error, [Error]\t, ERROR)
    XX(fatal, [Fatal]\t, FATAL)

#undef XX

private:
    static std::expected<std::string, std::string> get_current_time_string() {
        auto now = std::chrono::system_clock::now();
        time_t now_time = std::chrono::system_clock::to_time_t(now);
        tm local_time = *std::localtime(&now_time);

        // char buffer[100];
        constexpr size_t buf_length = 1000;
        std::array<char, buf_length> buffer {};
        if (0 == strftime(buffer.data(), buf_length, "%Y-%m-%d %H:%M:%S", &local_time)) {
            std::unexpected("fail to get currenttime");
        }
        return std::string(buffer.data());
    }

    static std::string apply_color(LogPriority pri, const std::string& text) {
        switch (pri) {
            case LogPriority::ERROR:
            case LogPriority::FATAL:
                return "\033[31m" + text + "\033[0m"; // red

            case LogPriority::WARN:
                return "\033[33m" + text + "\033[0m"; // yellow

            case LogPriority::INFO:
                return "\033[32m" + text + "\033[0m"; // green

            case LogPriority::DEBUG:
                return "\033[36m" + text + "\033[0m"; // cyan

            case LogPriority::TRACE:
                return "\033[90m" + text + "\033[0m"; // gray

            default:
                return text;
        }
    }

    void log(std::string pri, LogPriority msg_pri, const std::string& msg) {
        if (_enable_time_recording) {
            if (auto ret = get_current_time_string(); ret.has_value()) {
                auto str = std::format("{}\t", ret.value());
                pri += str;
            } else {
                std::println(std::cerr, "{}", ret.error());
            }
        }

        auto colored_output = apply_color(msg_pri, msg);
        auto colored_pri = apply_color(msg_pri, pri);

        std::ranges::for_each(_apprenders, [&](const auto& appender) {
            std::unique_lock<std::mutex> lock(_mtx);
            appender->log(colored_pri, msg_pri, colored_output);
        });
    }

    LogPriority _priority { LogPriority::TRACE };
    mutable std::mutex _mtx;
    std::vector<LogAppender::ptr> _apprenders;
    bool _enable_time_recording { false };
};

} // namespace logger
