#pragma once

#include <memory>
#include <modules/module.hpp>
#include <string>
#include <vector>

namespace server {

void run_server(
    const std::string& server_address,
    std::vector<std::unique_ptr<module::IModule>> modules
);

} // namespace server
