
#include <error/error.hpp>
#include <expected>
#include <toml++/toml.hpp>
namespace module {

using error::ModuleError;
using ModuleResult = std::expected<void, ModuleError>;
class IModule {
public:
    virtual ModuleResult load() = 0;
    virtual void unload() = 0;
    virtual std::string type() = 0;
    virtual ModuleResult parse_config(const toml::table* table) = 0;
    virtual ~IModule() = default;

private:
};

} // namespace module
