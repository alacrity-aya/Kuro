#pragma once

#include <arpa/inet.h>
#include <cpptrace/cpptrace.hpp>
#include <expected>
#include <fcntl.h>
#include <format>
#include <iostream>
#include <netinet/in.h>
#include <string>
#include <unistd.h>

namespace utils {
struct CommandResult {
    std::string output;
    int exitstatus;
    friend std::ostream& operator<<(std::ostream& os, const CommandResult& result) {
        os << "command exitstatus: " << result.exitstatus << " output: " << result.output;
        return os;
    }
    bool operator==(const CommandResult& rhs) const {
        return output == rhs.output && exitstatus == rhs.exitstatus;
    }
    bool operator!=(const CommandResult& rhs) const {
        return !(rhs == *this);
    }
};

class Command {
public:
    /**
             * Execute system command and get STDOUT result.
             * Regular system() only gives back exit status, this gives back output as well.
             * @param command system command to execute
             * @return commandResult containing STDOUT (not stderr) output & exitstatus
             * of command. Empty if command failed (or has no output). If you want stderr,
             * use shell redirection (2&>1).
             */
    static std::expected<CommandResult, std::string> exec(const std::string& command) {
        int exitcode = 0;
        std::array<char, 1048576> buffer {};
        std::string result;
#ifdef _WIN32
    #define popen _popen
    #define pclose _pclose
    #define WEXITSTATUS
#endif
        FILE* pipe = popen(command.c_str(), "r");
        if (pipe == nullptr) {
            return std::unexpected { "popen() failed" };
        }
        try {
            std::size_t bytesread;
            while ((bytesread =
                        std::fread(buffer.data(), sizeof(buffer.at(0)), sizeof(buffer), pipe))
                   != 0)
            {
                result += std::string(buffer.data(), bytesread);
            }
        } catch (...) {
            pclose(pipe);
            return std::unexpected { "std::fread() failed" };
            throw;
        }
        exitcode = WEXITSTATUS(pclose(pipe));
        return CommandResult { .output = result, .exitstatus = exitcode };
    }
};
} // namespace utils

namespace std {

template<>
struct formatter<utils::CommandResult, char> {
    static constexpr auto parse(format_parse_context& ctx) {
        return ctx.begin();
    }

    static auto format(const utils::CommandResult& cr, format_context& ctx) {
        return format_to(ctx.out(), "command exitstatus: {} output: {}", cr.exitstatus, cr.output);
    }
};
} // namespace std
