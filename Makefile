BPF_DIR = ./bpf
INTERNAL_EBPF_DIR = ./internal/ebpf

.PHONY: generate
generate:
	go generate ./...

.PHONY: build-agent
build-agent: generate
	go build -o bin/agent ./cmd/agent/main.go

.PHONY: clean
clean:
	rm -rf $(INTERNAL_EBPF_DIR)/*bpf*.go
	rm -rf $(INTERNAL_EBPF_DIR)/*.o
	rm -rf bin/
