#pragma once

#include "../logger/logger.hpp" // WTF: using angle brackets makes clangd clash
#include <arpa/inet.h>
#include <error/error.hpp>
#include <fcntl.h>
#include <memory>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>

// Systemd includes
#include <systemd/sd-bus.h>

namespace utils {

// --- Systemd Control Helper Class ---

namespace systemd {

    struct SdBusDeleter {
        void operator()(sd_bus* bus) const {
            sd_bus_unref(bus);
        }
        void operator()(sd_bus_message* msg) const {
            sd_bus_message_unref(msg);
        }
    };

    using BusPtr = std::unique_ptr<sd_bus, SdBusDeleter>;
    using MessagePtr = std::unique_ptr<sd_bus_message, SdBusDeleter>;

    // Helper to split args string into vector
    inline std::vector<std::string> split_args(const std::string& s) {
        std::istringstream iss(s);
        std::vector<std::string> result;
        std::string item;
        while (iss >> item) {
            result.push_back(item);
        }
        return result;
    }

    // Helper to handle dbus errors
    inline std::string get_bus_error(int ret, const sd_bus_error* error = nullptr) {
        if ((error != nullptr) && (sd_bus_error_is_set(error) != 0)) {
            return std::format("DBus error: {} - {}", error->name, error->message);
        }
        return std::format("Systemd error code: {}", -ret);
    }

} // namespace systemd

// Expose logic as inline functions in utils namespace
using error::ModuleResult;

struct ServiceStartOptions { // make clang-tidy happy
    std::string executable_path;
    std::string args;
    std::string service_id;
};

inline ModuleResult service_start(const ServiceStartOptions& option) {
    const auto& [executable_path, args, service_id] = option;

    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus* bus_raw = nullptr;
    sd_bus_message* m_raw = nullptr;
    int r;

    // 1. Connect to system bus
    r = sd_bus_default_system(&bus_raw);
    if (r < 0)
        return std::unexpected { error::ModuleError { error::ErrorCode::RUN_SHELL_CMD_FAILED,
                                                      "Failed to connect to system bus" } };
    systemd::BusPtr bus(bus_raw);

    // 2. Prepare method call: StartTransientUnit
    r = sd_bus_message_new_method_call(
        bus.get(),
        &m_raw,
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
        "StartTransientUnit"
    );
    if (r < 0)
        return std::unexpected { error::ModuleError { error::ErrorCode::RUN_SHELL_CMD_FAILED,
                                                      "Failed to create dbus message" } };
    systemd::MessagePtr m(m_raw);

    // 3. Append arguments: name and mode
    std::string service_name = service_id + ".service";
    r = sd_bus_message_append(m.get(), "ss", service_name.c_str(), "replace");
    if (r < 0)
        return std::unexpected { error::ModuleError { error::ErrorCode::RUN_SHELL_CMD_FAILED,
                                                      "Failed to append name/mode" } };

    // 4. Append Properties: a(sv)
    r = sd_bus_message_open_container(m.get(), 'a', "(sv)");
    if (r < 0)
        return std::unexpected { error::ModuleError { error::ErrorCode::RUN_SHELL_CMD_FAILED,
                                                      "Failed to open props container" } };

    // 4.1 Property: Description
    r = sd_bus_message_append(m.get(), "(sv)", "Description", "s", "Kuro-Flow-Control Service");
    if (r < 0)
        return std::unexpected { error::ModuleError { error::ErrorCode::RUN_SHELL_CMD_FAILED,
                                                      "Failed to append description" } };

    // 4.2 Property: Slice
    r = sd_bus_message_append(m.get(), "(sv)", "Slice", "s", "limit.slice");
    if (r < 0)
        return std::unexpected { error::ModuleError { error::ErrorCode::RUN_SHELL_CMD_FAILED,
                                                      "Failed to append slice" } };

    // 4.3 Property: ExecStart -> a(sasb)
    {
        r = sd_bus_message_open_container(m.get(), 'r', "sv"); // Struct for Property (Key, Value)
        if (r < 0)
            return std::unexpected { error::ModuleError { error::ErrorCode::RUN_SHELL_CMD_FAILED,
                                                          "Failed to open ExecStart prop" } };

        r = sd_bus_message_append(m.get(), "s", "ExecStart");
        if (r < 0)
            return std::unexpected { error::ModuleError { error::ErrorCode::RUN_SHELL_CMD_FAILED,
                                                          "Failed to append ExecStart key" } };

        r = sd_bus_message_open_container(m.get(), 'v', "a(sasb)"); // Variant
        if (r < 0)
            return std::unexpected { error::ModuleError { error::ErrorCode::RUN_SHELL_CMD_FAILED,
                                                          "Failed to open ExecStart variant" } };

        r = sd_bus_message_open_container(m.get(), 'a', "(sasb)"); // Array of ExecStart structs
        if (r < 0)
            return std::unexpected { error::ModuleError { error::ErrorCode::RUN_SHELL_CMD_FAILED,
                                                          "Failed to open ExecStart array" } };

        r = sd_bus_message_open_container(
            m.get(),
            'r',
            "sasb"
        ); // Struct: path, argv[], ignore_fail
        if (r < 0)
            return std::unexpected { error::ModuleError { error::ErrorCode::RUN_SHELL_CMD_FAILED,
                                                          "Failed to open ExecStart struct" } };

        // Path
        r = sd_bus_message_append(m.get(), "s", executable_path.c_str());

        // Argv array
        r = sd_bus_message_open_container(m.get(), 'a', "s");

        // Argv[0] MUST be the executable name/path
        sd_bus_message_append(m.get(), "s", executable_path.c_str());

        // Parse and append user args
        auto split_args = systemd::split_args(args);
        for (const auto& arg: split_args) {
            sd_bus_message_append(m.get(), "s", arg.c_str());
        }

        sd_bus_message_close_container(m.get()); // Close Argv array

        // Ignore failure bool
        r = sd_bus_message_append(m.get(), "b", 0);

        sd_bus_message_close_container(m.get()); // Close Struct
        sd_bus_message_close_container(m.get()); // Close Array of ExecStart
        sd_bus_message_close_container(m.get()); // Close Variant
        sd_bus_message_close_container(m.get()); // Close Property Struct
    }

    // Close Properties Array
    sd_bus_message_close_container(m.get());

    // 5. Append Aux: a(sa(sv)) - empty
    r = sd_bus_message_append(m.get(), "a(sa(sv))", 0);
    if (r < 0)
        return std::unexpected { error::ModuleError { error::ErrorCode::RUN_SHELL_CMD_FAILED,
                                                      "Failed to append aux" } };

    // 6. Send
    r = sd_bus_call(bus.get(), m.get(), 0, &error, nullptr);
    if (r < 0) {
        std::string err_msg = systemd::get_bus_error(r, &error);
        sd_bus_error_free(&error);
        auto& logger = logger::Logger::instance();
        logger.error("Systemd start failed: {}", err_msg);
        return std::unexpected { error::ModuleError { error::ErrorCode::RUN_SHELL_CMD_FAILED,
                                                      err_msg } };
    }

    auto& logger = logger::Logger::instance();
    logger.info("Started systemd service: {}", service_name);
    return {};
}

inline void service_stop(const std::string& uuid) {
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus* bus_raw = nullptr;

    if (sd_bus_default_system(&bus_raw) < 0)
        return;
    systemd::BusPtr bus(bus_raw);

    std::string service_name = uuid + ".service";

    // 1. StopUnit
    int r = sd_bus_call_method(
        bus.get(),
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
        "StopUnit",
        &error,
        nullptr,
        "ss",
        service_name.c_str(),
        "replace"
    );

    auto& logger = logger::Logger::instance();
    if (r < 0) {
        logger
            .warn("Failed to stop service {}: {}", service_name, systemd::get_bus_error(r, &error));
        sd_bus_error_free(&error);
    } else {
        logger.info("Stopped service: {}", service_name);
    }

    // 2. ResetFailedUnit (equivalent to systemctl reset-failed)
    // We reuse the connection, but errors need to be cleared
    sd_bus_error_free(&error);
    r = sd_bus_call_method(
        bus.get(),
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
        "ResetFailedUnit",
        &error,
        nullptr,
        "s",
        service_name.c_str()
    );

    if (r < 0) {
        // Only log warn since it might not have failed
        logger.warn("Reset failed unit {}: {}", service_name, systemd::get_bus_error(r, &error));
        sd_bus_error_free(&error);
    }
}

inline void service_status(const std::string& uuid) {
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus* bus_raw = nullptr;

    if (sd_bus_default_system(&bus_raw) < 0)
        return;
    systemd::BusPtr bus(bus_raw);

    std::string service_name = uuid + ".service";
    auto& logger = logger::Logger::instance();

    // To get properties, we first need to find the object path for the unit
    [[maybe_unused]] char* unit_path_raw = nullptr;
    int r = sd_bus_call_method(
        bus.get(),
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
        "GetUnit",
        &error,
        nullptr,
        "s",
        service_name.c_str()
    );

    if (r < 0) {
        logger.warn("Status: Service {} not found (or not active)", service_name);
        sd_bus_error_free(&error);
        return;
    }

    // Read the return value (Object Path)
    [[maybe_unused]] sd_bus_message* reply = sd_bus_get_current_message(
        bus.get()
    ); // Hacky way if using high level api, but sd_bus_call_method returns message in reply arg usually.
    // Wait, sd_bus_call_method has a reply output argument. Let's use correct signature.

    // Retrying GetUnit properly:
    sd_bus_message* m_reply = nullptr;
    r = sd_bus_call_method(
        bus.get(),
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
        "GetUnit",
        &error,
        &m_reply, // Capture reply
        "s",
        service_name.c_str()
    );

    if (r < 0) {
        logger.warn("Service {} not loaded", service_name);
        sd_bus_error_free(&error);
        return;
    }
    systemd::MessagePtr reply_ptr(m_reply);

    const char* object_path;
    r = sd_bus_message_read(m_reply, "o", &object_path);
    if (r < 0)
        return;

    // Now get ActiveState property
    char* state = nullptr;
    r = sd_bus_get_property_string(
        bus.get(),
        "org.freedesktop.systemd1",
        object_path,
        "org.freedesktop.systemd1.Unit",
        "ActiveState",
        &error,
        &state
    );

    if (r < 0) {
        logger.warn("Failed to get status for {}: {}", service_name, error.message);
        sd_bus_error_free(&error);
    } else {
        logger.info("Service {} status: {}", service_name, state);
        free(state); // sd_bus_get_property_string allocates
    }
}

inline std::optional<int> get_cgroup_fd(const std::string& uuid) {
    auto ret = open(std::format("/sys/fs/cgroup/limit.slice/{}.service", uuid).c_str(), O_RDONLY);
    if (ret < 0) { // Fixed: open returns -1 on error
        return std::nullopt;
    }
    return ret;
}

} // namespace utils
