#include <modules/ip.hpp>

namespace module {

ModuleResult IpModule::load() {
    logger.trace("{} is called ", __PRETTY_FUNCTION__);
    return {};
}

ModuleResult IpModule::parse_config(const toml::table* table) {
    logger.trace("{} is called ", __PRETTY_FUNCTION__);
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
