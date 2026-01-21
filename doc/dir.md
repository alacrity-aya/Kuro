distributed-net-emulator/
├── api/                    # Kubernetes CRD definitions (API structs)
│   └── v1alpha1/           # Versioning for your CRDs (e.g., NetworkTopology)
├── bpf/                    # eBPF C source code and headers
│   ├── headers/            # Common C headers (vmlinux.h, etc.)
│   └── tc_shaper.c         # The core traffic shaping eBPF program
├── cmd/                    # Entry points for your binaries (Main functions)
│   ├── controller/         # Main entry point for the Central Controller
│   └── agent/              # Main entry point for the Node Agent (DaemonSet)
├── deploy/                 # Deployment configurations
│   ├── k8s/                # Raw Kubernetes YAMLs (CRDs, RBAC, Deployments)
│   └── helm/               # (Optional) Helm charts
├── internal/               # Private library code (Core logic lives here)
│   ├── agent/              # Agent-specific logic (Pod watcher, Traffic reporter)
│   ├── controller/         # Controller business logic (Reconcilers)
│   ├── bpfloader/          # Go wrappers to load/attach eBPF programs
│   └── db/                 # Database access layer (Postgres/Prometheus)
├── pkg/                    # Public library code (Can be imported by other projects)
│   ├── proto/              # Generated gRPC code (Protocol Buffers)
│   └── utils/              # Shared utilities (logging, netns helpers)
├── proto/                  # Source .proto files for gRPC (Agent <-> Controller)
├── test/                   # Integration and E2E tests
│   ├── e2e/                # End-to-End tests (spinning up Kind clusters)
│   └── testdata/           # Sample data for testing
├── web/                    # Frontend code (React + TypeScript)
├── Makefile                # Build scripts (very important for eBPF/Go)
├── go.mod                  # Go module definition
└── README.md               # Project documentation
