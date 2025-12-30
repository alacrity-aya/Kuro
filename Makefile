BPF_DIR = ./bpf
INTERNAL_EBPF_DIR = ./internal/ebpf
BINARY_DIR = bin

.DEFAULT_GOAL := help

## generate: Generate eBPF Go bindings using bpf2go
.PHONY: generate
generate:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(BPF_DIR)/include/vmlinux.h
	go generate ./...

## build-agent: Compile the Agent binary
.PHONY: build-agent
build-agent: generate
	@mkdir -p $(BINARY_DIR)
	go build -o $(BINARY_DIR)/agent ./cmd/agent/main.go

## build-controller: Compile the Controller binary
.PHONY: build-controller
build-controller:
	@mkdir -p $(BINARY_DIR)
	go build -o $(BINARY_DIR)/controller ./cmd/controller/main.go

## build : Build both Agent and Controller
.PHONY: build
build: build-agent build-controller

## clean: Remove generated binaries and eBPF objects
.PHONY: clean
clean:
	rm -rf $(INTERNAL_EBPF_DIR)/*bpf*.go
	rm -rf $(INTERNAL_EBPF_DIR)/*.o
	rm -rf $(BINARY_DIR)/

## help: Show this help message
.PHONY: help
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' |  sed -e 's/^/ /'
