# Kuro - eBPF-based Distributed Network Simulator

## Project Overview

**Kuro** is a Kubernetes-native distributed network simulator that leverages eBPF for high-performance, kernel-level traffic control and network emulation. It enables users to define custom network topologies and simulate various network conditions (bandwidth, latency, jitter, packet loss) between containerized nodes.

### Core Purpose
- Simulate distributed network environments (drone swarms, IoT networks, microservices)
- Provide precise traffic shaping using eBPF EDT (Earliest Departure Time) algorithm
- Isolate simulation traffic from system/business traffic on shared infrastructure
- Collect real-time telemetry and metrics from simulated networks

### Key Technologies
- **Language:** Go 1.25+
- **eBPF:** Cilium/ebpf library, TC (Traffic Control), XDP programs
- **Kubernetes:** Controller-Runtime, Custom Resource Definitions (CRDs)
- **Communication:** gRPC (bi-directional streaming) between Agent and Controller
- **Metrics:** Prometheus-compatible endpoints

---

## Architecture

### Components

```
┌─────────────────────────────────────────────────────────────┐
│                    SIMULATION CONTROLLER                      │
│  - Parses YAML topologies                                     │
│  - Schedules K8s resources                                    │
│  - Calculates routing and bandwidth policies                  │
│  - gRPC Server (port 9090) + HTTP API (port 8080)            │
└─────────────────────────────────────────────────────────────┘
                              │
                    gRPC (bi-directional)
                              │
┌─────────────────────────────────────────────────────────────┐
│                      NODE AGENT (DaemonSet)                   │
│  - Local Pod watcher                                          │
│  - BPF program loader and manager                             │
│  - Traffic control execution                                  │
│  - Metrics collection (:8080/metrics)                        │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                    eBPF KERNEL LAYER                          │
│  - TC Egress: Download (host veth) + Upload (pod eth0)       │
│  - XDP Ingress: Physical NIC protection                       │
│  - EDT-based traffic shaping                                  │
└─────────────────────────────────────────────────────────────┘
```

### Data Plane (eBPF)

**Hook Points:**
1. **Download (Host → Pod):** TC Egress on host-side veth (`handle_edt_download`)
2. **Upload (Pod → Host):** TC Egress on pod-side eth0 (`handle_edt_upload`)
3. **Global Egress:** TC Egress on host physical NIC (`handle_eth0_egress`)
4. **Ingress Protection:** XDP on host physical NIC (`handle_xdp_ingress`)

**Traffic Isolation:**
- Simulation traffic: Priority 1, strict EDT rate limiting
- System traffic: Priority 0, deferred by 3ms (SYS_LATENCY_OFFSET_NS)
- Port bypass for SSH (22), Kubelet (10250), Metrics (9100)

**Key BPF Maps:**
- `config_map`: Global configuration (EDT horizon)
- `rate_map`: Per-interface bandwidth limits (Sim/Sys up/down)
- `topology_policy_map`: Per-link policies (bandwidth, latency, jitter, packet loss)
- `edt_download_state_map` / `edt_upload_state_map`: EDT state tracking
- `metrics_map`: Per-CPU flow statistics
- `latency_map`: Latency histogram

---

## Directory Structure

```
kuro/
├── api/
│   ├── crd/v1alpha1/          # Kubernetes CRD definitions
│   │   ├── networktopology_types.go
│   │   └── trafficcontrol_types.go
│   └── proto/v1/              # gRPC protocol definitions
│       └── simulation.proto
├── bpf/                       # eBPF C source code
│   ├── tc.c                   # Main TC/XDP programs
│   └── include/
│       ├── map.h              # BPF map definitions
│       └── helper.h           # Helper functions
├── cmd/                       # Entry points
│   ├── agent/main.go          # Agent binary
│   └── controller/main.go     # Controller binary
├── deploy/                    # Kubernetes manifests
│   ├── agent.yaml             # Agent DaemonSet
│   ├── controller.yaml        # Controller Deployment
│   ├── test-topology.yaml     # Sample NetworkTopology CR
│   └── test-traffic.yaml      # Sample TrafficControl CR
├── internal/
│   ├── agent/                 # Agent implementation
│   │   ├── agent.go           # Main agent logic
│   │   ├── bpf/               # BPF manager (Go bindings)
│   │   ├── opsapi/            # HTTP metrics service
│   │   ├── remote/            # gRPC client
│   │   └── watch/             # Local Pod watcher
│   ├── controller/            # Controller implementation
│   │   ├── controller.go      # Controller manager
│   │   ├── api/               # HTTP API server
│   │   ├── k8s/               # K8s reconcilers
│   │   └── rpc/               # gRPC server
│   └── domain/                # Domain models
├── test/
│   ├── bpf/                   # eBPF integration tests
│   ├── e2e/                   # End-to-end tests
│   └── benchmark/             # Performance benchmarks
├── docker/                    # Dockerfiles
├── scripts/                   # Build and test scripts
├── Makefile                   # Build automation
└── doc/                       # Design documentation
```

---

## Building and Running

### Prerequisites
- Go 1.25+
- LLVM/Clang (for eBPF compilation)
- bpftool
- Docker
- Kubernetes cluster (or Kind for local testing)

### Build Commands

```bash
# Generate protobuf Go code
make proto

# Generate eBPF Go bindings (requires bpftool and vmlinux.h)
make bpf

# Generate CRD DeepCopy methods and YAMLs
make generate

# Build all binaries
make build

# Build Docker images (use IMAGE_TAG=... to override)
make images

# Clean all generated files
make clean
```

### Running Locally

1. **Build images:**
   ```bash
   make images
   ```

2. **Deploy to Kubernetes:**
   ```bash
   kubectl apply -f deploy/controller.yaml
   kubectl apply -f deploy/agent.yaml
   ```

3. **Create a simulation topology:**
   ```bash
   kubectl apply -f deploy/test-topology.yaml
   kubectl apply -f deploy/test-traffic.yaml
   ```

### Environment Variables

**Agent:**
- `NODE_NAME`: Kubernetes node name (from Downward API)
- `CONTROLLER_ADDR`: Controller gRPC address (default: `127.0.0.1:9090`)
- `CONTAINERD_ADDRESS`: Containerd socket path

**Controller:**
- Flags: `-grpc-port`, `-http-port`, `-metrics-bind-address`

---

## Testing

### Test Script (`scripts/test.sh`)

```bash
# Run standard unit tests (non-root)
./scripts/test.sh -std

# Run eBPF integration tests (requires sudo)
./scripts/test.sh -bpf

# Run Kubernetes integration tests
./scripts/test.sh -k8s

# Run benchmarks
./scripts/test.sh -benchmark

# Run all tests
./scripts/test.sh -all

# Options
./scripts/test.sh -std --verbose --no-cache
```

### Test Tags
- `!bpf,!k8s,!benchmark`: Standard unit tests
- `bpf`: eBPF tests (requires root/capabilities)
- `k8s`: Kubernetes integration tests
- `benchmark`: Performance benchmarks

---

## Development Conventions

### Code Style
- Go: Standard `gofmt` formatting
- BPF C: Clang-format (see `bpf/.clang-format`)

### Naming Conventions
- **CRDs:** `NetworkTopology`, `TrafficControl` (group: `simulation.kuro.io`)
- **Protobuf:** PascalCase for messages, snake_case for fields
- **BPF Maps:** snake_case with `_map` suffix
- **Go Packages:** lowercase, single word preferred

### Key Patterns

**1. BPF Map Key Encoding:**
- Rate map: Key = `ifindex` (per-interface)
- Topology policy: Key = `{src_ip, dst_ip}` (per-link)
- EDT state: Key = `ifindex * 2 + (is_sim ? 1 : 0)` (per-direction, per-traffic-type)

**2. Bandwidth Conversion:**
```go
// Convert bps to scaled cost for EDT
func bpsToScaledCost(bps uint64) uint64 {
    if bps == 0 {
        return 0
    }
    // cost = (NSEC_PER_SEC * 8 * 65536) / bps
    return (NsecPerSec * 8 * ScaleFactor) / bps
}
```

**3. Traffic Classification Flow:**
1. Parse ports → Check system port bypass
2. Build policy key `{src_ip, dst_ip}`
3. Lookup `topology_policy_map` → Found = Sim, Not found = Sys

### Error Handling
- Agent: Log errors and continue running (resilient)
- Controller: Update CRD status with error messages
- BPF: Graceful fallback (return `TC_ACT_OK` on lookup failure)

---

## CRD Specifications

### NetworkTopology
Defines a group of simulation nodes (pods):
```yaml
spec:
  nodeGroups:
    - name: drones
      replicas: 10
      image: simulation-node:latest
      labels:
        role: drone
```

### TrafficControl
Defines link policies between node groups:
```yaml
spec:
  source:
    matchLabels: { role: drone }
  destination:
    matchLabels: { role: ground-station }
  policy:
    bandwidth: "10Mbps"
    latency: "50ms"
    jitter: "10ms"
    packetLoss: "0.5%"
```

---

## gRPC Protocol

**Service:** `SimulationAgentService`

**Messages (Agent → Controller):**
- `Heartbeat`: Node liveness and pod count
- `PodLifecycleEvent`: Pod added/modified/deleted
- `CommandAck`: Acknowledgment for controller commands

**Messages (Controller → Agent):**
- `ApplyLinkPolicy`: Set per-link policy in `topology_policy_map`
- `ApplyPodPolicy`: Set interface rate limits in `rate_map`
- `ApplyNodePolicy`: Set XDP ingress limits

---

## Metrics

Agent exposes Prometheus metrics at `:8080/metrics`:
- Per-interface packet/byte counters
- Drop statistics
- Latency histogram

---

## Important Files

| File | Purpose |
|------|---------|
| `bpf/tc.c` | Core eBPF traffic control logic |
| `bpf/include/map.h` | BPF map structure definitions |
| `internal/agent/bpf/manager.go` | Go BPF loader and manager |
| `internal/controller/k8s/traffic_controller.go` | TrafficControl reconciler |
| `api/proto/v1/simulation.proto` | gRPC API contract |
| `Makefile` | Build automation |

---

## Debugging Tips

1. **Enable BPF debug prints:**
   ```c
   // In bpf/include/helper.h
   #define ENABLE_PRINT 1
   ```

2. **Check BPF map contents:**
   ```bash
   sudo bpftool map list
   sudo bpftool map dump name rate_map
   ```

3. **Verify TC attachment:**
   ```bash
   sudo tc filter show dev <interface> egress
   ```

4. **Check XDP attachment:**
   ```bash
   sudo ip link show <interface>
   ```

---

## Known Issues / TODOs

1. **FIXME in `controller.go:triggerResyncForNode`:** When Controller restarts, all agents reconnect simultaneously, causing K8s API throttling (50 TrafficControls × 100 nodes = 5000 patches).

2. **TODO in `map.h`:** `link_policy` structure can be improved.

3. **TODO in `helper.h`:** Remove unnecessary if statement in `parse_ipv4`.

4. **Project status:** Work In Progress - expect breaking changes.
