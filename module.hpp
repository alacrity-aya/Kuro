#pragma once

#include <bpf/libbpf.h>
#include <expected>
#include <functional>
#include <memory>
#include <print>
#include <toml++/toml.hpp>
#include <vector>
#include <yaml-cpp/yaml.h>

struct EbpfModule {
    std::string name;
    std::string toml_key;
    std::function<int(const toml::node& node)> load;
    std::function<void(void)> unload;

    ~EbpfModule() {
        if (unload) {
            std::println("unload module {}...", this->name);
            unload();
        }
    }
};

using RingBufferPtr = std::unique_ptr<ring_buffer, std::function<void(ring_buffer*)>>;
using EbpfModulePtr = std::unique_ptr<EbpfModule>;

class ModuleManager {
private:
    std::vector<EbpfModulePtr> _modules;
    std::vector<RingBufferPtr> _ring_buffers;

    ModuleManager() = default;
    ~ModuleManager() = default;

public:
    ModuleManager(const ModuleManager&) = delete;
    ModuleManager& operator=(const ModuleManager&) = delete;

    static ModuleManager& instance() {
        static ModuleManager instance;
        return instance;
    }

    [[nodiscard]] const auto& get_modules() const {
        return this->_modules;
    }

    void add_module(EbpfModulePtr mod) {
        this->_modules.push_back(std::move(mod));
    }

    [[nodiscard]] const auto& get_ring_buffers() const {
        return this->_ring_buffers;
    }

    void add_ring_buffer(RingBufferPtr ring_buffer) {
        this->_ring_buffers.push_back(std::move(ring_buffer));
    }

    [[nodiscard]] std::expected<void, std::string> poll_ring_buffer(int timeout_ms) {
        for (auto& rb: this->_ring_buffers) {
            int err = ring_buffer__poll(rb.get(), timeout_ms);
            if (err == -EINTR) {
                continue;
            }
            if (err < 0) {
                return std::unexpected<std::string>("ring_buffer__poll error");
            }
        }
        return {};
    }
};
