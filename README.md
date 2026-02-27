<div align="center">
    <img src="assert/kuro.png" alt="kuro CG" width="40%">
    <h1>Kuro — eBPF-based Distributed Network Simulator</h1>
    <p>Simulate realistic network conditions between Kubernetes pods using eBPF traffic control.</p>
</div>

---

## ✨ Features

- **eBPF Traffic Shaping** — Kernel-level bandwidth, latency, jitter, and packet-loss control via EDT scheduling.
- **Traffic Isolation** — Separate simulation traffic from system traffic on shared infrastructure.
- **Kubernetes-Native** — Manage topologies and traffic rules through CRDs (`NetworkTopology`, `TrafficControl`).
- **Modern Web UI** — Visual topology editor (ReactFlow), real-time metrics (ECharts), YAML editor (Monaco).
- **Prometheus Metrics** — Per-pod, per-direction traffic statistics exposed at `:8080/metrics`.

## 🏗 Architecture

```
 Web Frontend (React)  ──REST──▶  Simulation Controller  ──gRPC──▶  Node Agent (DaemonSet)
                                        │                                │
                                   K8s API / CRDs                  eBPF TC / XDP
```

See [docs/design.md](docs/design.md) for the full architecture breakdown.

## 🚀 Quick Start

```bash
# Build everything
make build images

# Deploy to Kubernetes
kubectl apply -f deploy/controller.yaml
kubectl apply -f deploy/agent.yaml

# Create a sample simulation
kubectl apply -f deploy/test-topology.yaml
kubectl apply -f deploy/test-traffic.yaml

# Run the frontend dev server
cd frontend && npm install && npm run dev
```

## 📖 Documentation

| Document | Description |
|----------|-------------|
| [AGENTS.md](AGENTS.md) | Comprehensive project reference (architecture, API, conventions) |
| [docs/design.md](docs/design.md) | System design overview |
| [docs/crd-design.md](docs/crd-design.md) | CRD detailed specification |
| [docs/traffic_control.md](docs/traffic_control.md) | Traffic control data-plane flow diagrams |
| [docs/frontend-backend-api.md](docs/frontend-backend-api.md) | Frontend ↔ Backend API contract |
| [docs/grafana-setup.md](docs/grafana-setup.md) | Grafana dashboard setup guide |

## 🧪 Testing

```bash
# Go unit tests
./scripts/test.sh -std

# eBPF integration tests (requires root)
./scripts/test.sh -bpf

# Frontend tests
cd frontend && npx vitest run
```

## 📄 License

🚧 This project is currently a Work In Progress.
