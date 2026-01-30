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
PROTO_SRC_DIR     = api/v1
PROTO_FILES       = $(wildcard $(PROTO_SRC_DIR)/*.proto)

.DEFAULT_GOAL := help

# ==============================================================================
# Helper Logic
# ==============================================================================
# Shell snippet to measure time
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
build-controller: proto
	@printf "$(COLOR_BLUE)==> Building Controller binary...$(COLOR_RESET)\n"
	@mkdir -p $(BINARY_DIR)
	@$(TIME_START); \
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BINARY_DIR)/controller ./cmd/controller/main.go; \
	$(TIME_END)
	@printf "$(COLOR_GREEN)✓ Controller binary built at $(BINARY_DIR)/controller$(COLOR_RESET)\n"

## images: Build images
.PHONY: images
images: build-agent build-controller
	@printf "$(COLOR_BLUE)==> Building Docker images...$(COLOR_RESET)\n"
	@docker build -f docker/Dockerfile.agent -t kuro-agent:dev .
	@docker build -f docker/Dockerfile.controller -t kuro-controller:dev .
	@printf "$(COLOR_GREEN)✓ Docker images built$(COLOR_RESET)\n"

## build: Build both Agent and Controller
.PHONY: build
build: build-agent build-controller

## clean: Remove generated binaries and eBPF objects
.PHONY: clean
clean:
	@printf "$(COLOR_BLUE)==> Cleaning up...$(COLOR_RESET)\n"
	@rm -rf $(INTERNAL_EBPF_DIR)/*bpf*.go
	@rm -rf $(INTERNAL_EBPF_DIR)/*.o
	@rm -rf $(BINARY_DIR)/
	@find . -name "*.pb.go" -delete
	@printf "$(COLOR_GREEN)✓ Clean complete$(COLOR_RESET)\n"

## help: Show this help message
.PHONY: help
help:
	@printf "$(COLOR_BOLD)Usage: make [target]$(COLOR_RESET)\n\n"
	@printf "$(COLOR_BOLD)Targets:$(COLOR_RESET)\n"
	@awk '/^## [a-zA-Z_-]+:/ { \
		nb = index($$0, ":"); \
		target = substr($$0, 4, nb-4); \
		desc = substr($$0, nb+1); \
		gsub(/^[ \t]+/, "", desc); \
		printf "  $(COLOR_CYAN)%-20s$(COLOR_RESET) %s\n", target, desc \
	}' $(MAKEFILE_LIST)
