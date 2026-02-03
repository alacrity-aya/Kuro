# ==============================================================================
# Colors and Variables
# ==============================================================================
# Standard ANSI Colors
COLOR_RESET   := \033[0m
COLOR_GREEN   := \033[32m
COLOR_BLUE    := \033[34m
COLOR_YELLOW  := \033[33m
COLOR_RED     := \033[31m
COLOR_CYAN    := \033[36m
COLOR_BOLD    := \033[1m

# Directories
BPF_DIR           = ./bpf
INTERNAL_EBPF_DIR = ./internal/ebpf
BINARY_DIR        = bin
PROTO_SRC_DIR     = api/proto/v1
PROTO_FILES       = $(wildcard $(PROTO_SRC_DIR)/*.proto)
CRD_DIR           = deploy/crd

# Tool Versions
CONTROLLER_GEN_VER := latest
CONTROLLER_GEN     := $(BINARY_DIR)/controller-gen

# Image Configuration
IMAGE_TAG        ?= dev
AGENT_IMG        := kuro-agent:$(IMAGE_TAG)
CONTROLLER_IMG   := kuro-controller:$(IMAGE_TAG)

.DEFAULT_GOAL := help

# ==============================================================================
# Helper Logic
# ==============================================================================
TIME_START = start=$$(date +%s)
TIME_END   = end=$$(date +%s); runtime=$$((end-start)); \
             printf "$(COLOR_YELLOW)⏱  Time taken: $${runtime}s$(COLOR_RESET)\n"

# ==============================================================================
# Targets
# ==============================================================================

## proto: Compile protobuf files for Go
.PHONY: proto
proto:
	@printf "$(COLOR_BLUE)==> Compiling Protobuf files...$(COLOR_RESET)\n"
	@protoc -I . \
		-I $(PROTO_SRC_DIR) \
		--go_out=. \
		--go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		$(PROTO_FILES)
	@printf "$(COLOR_GREEN)✓ Protobuf compiled successfully$(COLOR_RESET)\n"

## bpf: Generate eBPF Go bindings using bpf2go
.PHONY: bpf
bpf:
	@printf "$(COLOR_BLUE)==> Generating eBPF Go bindings...$(COLOR_RESET)\n"
	@if [ ! -f $(BPF_DIR)/include/vmlinux.h ]; then \
		echo "  -> Dumping vmlinux.h..."; \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(BPF_DIR)/include/vmlinux.h; \
	fi
	@go generate ./...
	@printf "$(COLOR_GREEN)✓ eBPF bindings generated$(COLOR_RESET)\n"

## generate: Generate DeepCopy methods and CRD YAMLs
.PHONY: generate
generate:
	@printf "$(COLOR_BLUE)==> Installing controller-gen & Generating code...$(COLOR_RESET)\n"
	@mkdir -p $(BINARY_DIR)
	@GOBIN=$(abspath $(BINARY_DIR)) go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VER)
	@# 1. Generate DeepCopy code (zz_generated.deepcopy.go)
	@$(CONTROLLER_GEN) object paths="./api/..."
	@# 2. Generate CRD YAML manifests
	@mkdir -p $(CRD_DIR)
	@$(CONTROLLER_GEN) crd paths="./api/..." output:crd:artifacts:config=$(CRD_DIR)
	@printf "$(COLOR_GREEN)✓ Code generation complete (DeepCopy & CRDs)$(COLOR_RESET)\n"

## build-agent: Compile the Agent binary
.PHONY: build-agent
build-agent: proto bpf
	@printf "$(COLOR_BLUE)==> Building Agent binary...$(COLOR_RESET)\n"
	@mkdir -p $(BINARY_DIR)
	@$(TIME_START); \
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BINARY_DIR)/agent ./cmd/agent/main.go; \
	$(TIME_END)
	@printf "$(COLOR_GREEN)✓ Agent binary built at $(BINARY_DIR)/agent$(COLOR_RESET)\n"

## build-controller: Compile the Controller binary
.PHONY: build-controller
build-controller: proto generate
	@printf "$(COLOR_BLUE)==> Building Controller binary...$(COLOR_RESET)\n"
	@mkdir -p $(BINARY_DIR)
	@$(TIME_START); \
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BINARY_DIR)/controller ./cmd/controller/main.go; \
	$(TIME_END)
	@printf "$(COLOR_GREEN)✓ Controller binary built at $(BINARY_DIR)/controller$(COLOR_RESET)\n"

## images: Build Docker images (use IMAGE_TAG=... to override)
.PHONY: images
images: build-agent build-controller
	@printf "$(COLOR_BLUE)==> Building Docker images [Tag: $(IMAGE_TAG)]...$(COLOR_RESET)\n"
	@docker build -f docker/Dockerfile.agent -t $(AGENT_IMG) .
	@docker build -f docker/Dockerfile.controller -t $(CONTROLLER_IMG) .
	@printf "$(COLOR_GREEN)✓ Docker images built: $(AGENT_IMG), $(CONTROLLER_IMG)$(COLOR_RESET)\n"

## build: Build both Agent and Controller binaries
.PHONY: build
build: build-agent build-controller

## clean: Remove generated binaries, eBPF objects, CRDs and Docker images
.PHONY: clean
clean:
	@printf "$(COLOR_BLUE)==> Cleaning up...$(COLOR_RESET)\n"
	@rm -rf $(INTERNAL_EBPF_DIR)/*bpf*.go
	@rm -rf $(INTERNAL_EBPF_DIR)/*.o
	@rm -rf $(BINARY_DIR)/
	@rm -rf $(CRD_DIR)/
	@docker rmi $(AGENT_IMG) $(CONTROLLER_IMG) >/dev/null 2>&1 || true
	@find . -name "*.pb.go" -delete
	@find . -name "zz_generated.deepcopy.go" -delete
	@printf "$(COLOR_GREEN)✓ Clean complete$(COLOR_RESET)\n"

## help: Show this help message
.PHONY: help
help:
	@printf "$(COLOR_BOLD)Usage: make [target] [IMAGE_TAG=tag]$(COLOR_RESET)\n\n"
	@printf "$(COLOR_BOLD)Targets:$(COLOR_RESET)\n"
	@awk '/^## [a-zA-Z_-]+:/ { \
		nb = index($$0, ":"); \
		target = substr($$0, 4, nb-4); \
		desc = substr($$0, nb+1); \
		gsub(/^[ \t]+/, "", desc); \
		printf "  $(COLOR_CYAN)%-20s$(COLOR_RESET) %s\n", target, desc \
	}' $(MAKEFILE_LIST)
