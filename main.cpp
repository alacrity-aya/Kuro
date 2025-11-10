
#include <bpf/libbpf.h>
#include <csignal>
#include <module.hpp>

namespace {

volatile bool running = true;

void on_signal(int) {
    running = false;
}

} // namespace

int main(int argc, char* argv[]) {
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    auto deleter = [](auto* ring_buf) { ring_buffer__free(ring_buf); };
    auto& manager = ModuleManager::instance();

    return 0;
}
