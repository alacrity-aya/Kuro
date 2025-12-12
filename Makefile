# ------------------------------------------------------------------------------
# Makefile for kuro eBPF project
# Implements 'build' and 'run' targets for code generation and execution.
# ------------------------------------------------------------------------------

# Define project variables
BINARY_NAME := kuro
GEN_DIR := gen
BUILD_DIR := bin

# RPC generation
PROTO_SRC := proto/kuro.proto 
PROTO_OUT_DIR := proto

# Define the list of generated files to be cleaned
GENERATED_FILES := $(GEN_DIR)/tc_bpfeb.go $(GEN_DIR)/tc_bpfeb.o $(GEN_DIR)/tc_bpfel.go $(GEN_DIR)/tc_bpfel.o
GENERATED_FILES += $(PROTO_OUT_DIR)/kuro.pb.go $(PROTO_OUT_DIR)/kuro_grpc.pb.go

# Define phonies targets
.PHONY: all build run clean clean_gen proto

# Default target: build
all: build

# --------------------
# Executes cleanup, code generation, and final compilation.
# --------------------
build: clean_gen proto
	@echo "-> Running go generate..."
	go generate ./...
	@echo "-> Running go build..."
	go build -o $(BUILD_DIR)/$(BINARY_NAME)

# Helper target: Cleans generated files
clean_gen:
	@echo "-> Cleaning generated files in $(GEN_DIR)/"
	rm -f $(GENERATED_FILES)

proto:
	@echo "-> Compiling protobuf files..."
	protoc --go_out=$(PROTO_OUT_DIR) --go_opt=paths=source_relative \
	       --go-grpc_out=$(PROTO_OUT_DIR) --go-grpc_opt=paths=source_relative \
	       -Iproto $(PROTO_SRC)
	@echo "Protobuf code generated in $(PROTO_OUT_DIR)/"

# --------------------
# Builds the project and runs the compiled binary with sudo.
# --------------------
run: build
	@echo "-> Running $(BINARY_NAME) with sudo..."
	@if [ ! -f "./$(BUILD_DIR)/$(BINARY_NAME)" ]; then \
		echo "Error: Binary ./$(BINARY_NAME) not found. Build failed."; \
		exit 1; \
	fi
	sudo ./$(BUILD_DIR)/$(BINARY_NAME)

# --------------------
# CLEAN Target
# Removes the built binary and all generated source/object files.
# --------------------
clean:
	@echo "-> Cleaning built binary and generated files."
	rm -rf $(BUILD_DIR) 
	rm -f $(GENERATED_FILES)
