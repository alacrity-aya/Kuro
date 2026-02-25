# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Kuro is an eBPF-based distributed network simulator for Kubernetes. It enables users to define network topologies and simulate various network conditions (bandwidth limits, latency, jitter, packet loss) between containers using eBPF traffic control.

## Architecture

The project uses a **Hub-and-Spoke** architecture with three layers:

1. **Simulation Controller** (`cmd/controller/`, `internal/controller/`): The "brain" - single instance that parses user topologies, schedules K8s resources, and issues policies to Agents via gRPC
2. **Node Agent** (`cmd/agent/`, `internal/agent/`): The "hands and feet" - DaemonSet on each K8s node, handles eBPF program mounting, network hooking, and traffic control execution
3. **eBPF Kernel Layer** (`bpf/`): The "muscle" - TC and XDP programs for packet interception, shaping, and statistics collection

### Traffic Control Hook Points

- **Download (Host→Pod)**: TC Egress on host-side Veth (`handle_edt_download`)
- **Upload (Pod→Host)**: TC Egress on Pod-side eth0 (`handle_edt_upload`)
- **Ingress Protection**: XDP on physical NIC (`handle_xdp_ingress`)

### Communication

- **Controller ↔ Agent**: gRPC bi-directional streaming via `api/proto/v1/simulation.proto`
- **Metrics**: Prometheus format exposed at `:8080/metrics` per Agent
- **Frontend ↔ Backend**: REST API via `/api/v1/`

## Build Commands

```bash
# Build all binaries (requires protoc, bpftool, go)
make build

# Build individual components
make build-agent      # Build agent binary
make build-controller # Build controller binary

# Generate code
make proto      # Compile protobuf files
make bpf        # Generate eBPF Go bindings (bpf2go)
make generate   # Generate DeepCopy methods and CRD YAMLs

# Build Docker images
make images IMAGE_TAG=dev

# Clean generated files
make clean
```

## Test Commands

### Go Tests
```bash
# Run all Go tests
go test ./...

# Run tests for a specific package
go test ./internal/controller/...
go test ./internal/agent/...
go test ./test/e2e/...
go test ./test/bpf/...

# Run a single test
go test ./internal/controller/k8s -run TestTrafficController
```

### Frontend Tests
```bash
cd frontend
npm run test          # Run tests in watch mode
npm run test:run      # Run tests once
npm run test:coverage # Run with coverage
```

## Frontend Development

The frontend is a React 19 + TypeScript application using Vite:

```bash
cd frontend
npm install           # Install dependencies
npm run dev           # Start dev server (proxies /api to :8080)
npm run build         # Production build
npm run lint          # Run ESLint
```

### Frontend Architecture

- **UI Framework**: React 19 with TypeScript
- **State Management**: Zustand
- **Routing**: react-router-dom
- **Topology Visualization**: reactflow + dagre for auto-layout
- **Charts**: echarts for metrics visualization
- **YAML Editor**: Monaco Editor
- **API Client**: Mock/Real API toggle via `VITE_USE_MOCK_API` environment variable
- **Data Fetching**: @tanstack/react-query

### Key Frontend Directories

- `src/pages/` - Route-level page components (TopologyEditor, Dashboard, MetricsPage)
- `src/components/topology/` - Topology canvas, node/link configuration panels
- `src/components/metrics/` - Charts and metrics visualization
- `src/components/tsn/` - Time-Sensitive Networking components
- `src/api/` - API client with mock and real implementations
- `src/hooks/` - Custom React hooks (useHistory for undo/redo, useAutoRefresh)

## Key Files and Directories

| Path | Description |
|------|-------------|
| `cmd/agent/main.go` | Agent entry point |
| `cmd/controller/main.go` | Controller entry point |
| `api/proto/v1/simulation.proto` | gRPC protocol definitions |
| `api/crd/v1alpha1/` | Kubernetes CRD type definitions |
| `bpf/` | eBPF C programs (TC, XDP) |
| `internal/agent/bpf/` | Go eBPF bindings and manager |
| `internal/controller/k8s/` | Kubernetes controllers |
| `internal/controller/api/` | REST API server |
| `internal/domain/models.go` | Domain model definitions |
| `deploy/` | K8s manifests |
| `test/e2e/` | End-to-end integration tests |
| `test/bpf/` | eBPF-specific tests |

## CRD Types

- **TrafficControl** (`api/crd/v1alpha1/trafficcontrol_types.go`): Defines traffic shaping rules between source and destination pods with policy (bandwidth, latency, jitter, packet loss)

## gRPC Messages

Key message types in `simulation.proto`:
- `Heartbeat`: Agent liveness status
- `PodLifecycleEvent`: Pod add/modify/delete events
- `ApplyLinkPolicy`: Unidirectional link properties (bandwidth, latency, jitter, packet loss)
- `ApplyPodPolicy`: Per-pod rate limits (sim/sys upload/download)
- `ApplyNodePolicy`: Node-level ingress limits

## Requirements

- Go 1.25+
- Linux kernel with BTF support (for eBPF)
- protoc (Protocol Buffers compiler)
- bpftool (for vmlinux.h generation)
- Node.js 18+ (for frontend)
- Kubernetes cluster (for deployment)
