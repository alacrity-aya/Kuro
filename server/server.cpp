#include <server/server.hpp>

#include <atomic>
#include <csignal>
#include <google/protobuf/empty.pb.h>
#include <grpcpp/grpcpp.h>
#include <kuro.grpc.pb.h>
#include <kuro.pb.h>
#include <logger/logger.hpp>

namespace server {

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;

namespace {
    std::atomic<grpc::Server*> g_server_ptr { nullptr };

    void handle_signal(int signal) {
        if (auto* server = g_server_ptr.load()) {
            logger::warn("Received signal {}, shutting down server...", signal);
            server->Shutdown();
        }
    }
} // namespace

// --- Service ---
class RateCalculatorImpl final: public kuro::RateCalculator::Service {
public:
    explicit RateCalculatorImpl(std::vector<std::unique_ptr<module::IModule>> modules):
        modules_(std::move(modules)) {}

    ~RateCalculatorImpl() override {
        logger::info("Unloading modules...");
        for (auto& module: modules_) {
            module->unload();
        }
    }

    Status CalcRate(
        [[maybe_unused]] ServerContext* context,
        [[maybe_unused]] const google::protobuf::Empty* request,
        kuro::FlowRate* reply
    ) override {
        module::FlowRate aggregated_rate = calculate_aggregated_rate();

        reply->set_accepted_bytes_rate(aggregated_rate.accepted_bytes_rate);
        reply->set_dropped_bytes_rate(aggregated_rate.dropped_bytes_rate);
        reply->set_accepted_packets_rate(aggregated_rate.accepted_packets_rate);
        reply->set_dropped_packets_rate(aggregated_rate.dropped_packets_rate);

        return Status::OK;
    }

private:
    std::vector<std::unique_ptr<module::IModule>> modules_;

    module::FlowRate calculate_aggregated_rate() {
        module::FlowRate total_rate = {};
        for (const auto& module_ptr: modules_) {
            module::FlowRate rate = module_ptr->calc_rate();
            total_rate.accepted_bytes_rate += rate.accepted_bytes_rate;
            total_rate.dropped_bytes_rate += rate.dropped_bytes_rate;
            total_rate.accepted_packets_rate += rate.accepted_packets_rate;
            total_rate.dropped_packets_rate += rate.dropped_packets_rate;
        }
        return total_rate;
    }
};

void run_server(
    const std::string& server_address,
    std::vector<std::unique_ptr<module::IModule>> modules
) {
    RateCalculatorImpl service(std::move(modules));

    ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);

    std::unique_ptr<Server> server(builder.BuildAndStart());
    if (!server) {
        logger::error("Failed to start server on {}", server_address);
        return;
    }
    logger::info("Server listening on {}", server_address);

    g_server_ptr.store(server.get());
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    server->Wait();

    g_server_ptr.store(nullptr);
    logger::info("Server stopped.");
}

} // namespace server
