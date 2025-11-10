#pragma once

#include <filesystem>
#include <optional>
#include <string>

namespace utils {

namespace fs = std::filesystem;
inline std::optional<fs::path>
find_project_root(const std::string& landmark_file_name = "README.txt") {
    fs::path current_dir = fs::current_path();

    while (current_dir.has_parent_path() && current_dir != current_dir.parent_path()) {
        fs::path landmark_path = current_dir / landmark_file_name;

        if (fs::exists(landmark_path)) {
            return current_dir;
        }

        current_dir = current_dir.parent_path();
    }

    return std::nullopt;
}

template<typename Derived>
class Singleton {
public:
    static Derived& instance() {
        static Derived inst;
        return inst;
    }

    Singleton(const Singleton&) = delete;
    Singleton& operator=(const Singleton&) = delete;
    Singleton(Singleton&&) = delete;
    Singleton& operator=(Singleton&&) = delete;

protected:
    Singleton() = default;
    ~Singleton() = default;
};

} // namespace utils
