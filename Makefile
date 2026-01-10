# ebpf
BPF_DIR = ./bpf
INTERNAL_EBPF_DIR = ./internal/ebpf
BINARY_DIR = bin

# protobuf
PROTO_SRC_DIR = api/proto/v1
PROTO_OUT_DIR = .
PROTO_FILE = $(PROTO_SRC_DIR)/control.proto

.DEFAULT_GOAL := help

## proto: Compile protobuf files for Go
.PHONY: proto
proto:
	protoc -I . \
	       -I $(PROTO_SRC_DIR) \
	       --go_out=. --go_opt=paths=source_relative \
	       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
	       $(PROTO_FILE)

## bpf: Generate eBPF Go bindings using bpf2go
.PHONY: bpf
bpf:
	@if [ ! -f $(BPF_DIR)/include/vmlinux.h ]; then \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(BPF_DIR)/include/vmlinux.h; \
	fi
	go generate ./...

## build-agent: Compile the Agent binary
.PHONY: build-agent
build-agent: proto bpf
	@mkdir -p $(BINARY_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BINARY_DIR)/agent ./cmd/agent/main.go

## build-controller: Compile the Controller binary
.PHONY: build-controller
build-controller: proto
	@mkdir -p $(BINARY_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BINARY_DIR)/controller ./cmd/controller/main.go

## images: Build images
.PHONY: images
images: build-agent build-controller
	docker build -f docker/Dockerfile.agent -t kuro-agent:dev .
	docker build -f docker/Dockerfile.controller -t kuro-controller:dev .

## build : Build both Agent and Controller
.PHONY: build
build: build-agent build-controller

## clean: Remove generated binaries and eBPF objects
.PHONY: clean
clean:
	rm -rf $(INTERNAL_EBPF_DIR)/*bpf*.go
	rm -rf $(INTERNAL_EBPF_DIR)/*.o
	rm -rf $(BINARY_DIR)/
	@find . -name "*.pb.go" -delete

## help: Show this help message
.PHONY: help
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' |  sed -e 's/^/ /'
