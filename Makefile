# ------------------------------------------------------------------------------
# Makefile for kuro eBPF project
# Builds data panel & control panel binaries
# ------------------------------------------------------------------------------

# --------------------
# Project variables
# --------------------
BUILD_DIR := bin

DATA_BIN := $(BUILD_DIR)/kuro-data
CONTROL_BIN := $(BUILD_DIR)/kuro-control

CMD_DIR := cmd

GEN_DIR := gen

PROTO_DIR := proto
PROTO_SRC := $(shell find $(PROTO_DIR) -name "*.proto")

# --------------------
# Generated files
# --------------------
GENERATED_FILES := \
	$(GEN_DIR)/tc_bpfeb.go \
	$(GEN_DIR)/tc_bpfeb.o \
	$(GEN_DIR)/tc_bpfel.go \
	$(GEN_DIR)/tc_bpfel.o \
	$(PROTO_DIR)/kuro.pb.go \
	$(PROTO_DIR)/kuro_grpc.pb.go

# --------------------
# Phony targets
# --------------------
.PHONY: all build data control proto clean clean_gen run-data run-control ebpf

# --------------------
# Default target
# --------------------
all: build

# --------------------
# Help target
# --------------------
help:
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@echo "Project Targets (Build & Run):"
	@echo "------------------------------"
	@echo "  all            Builds all components (Default target)."
	@echo "  build          Equivalent to 'all': cleans generated files, generates proto, builds eBPF/Go code, then builds data and control binaries."
	@echo "  data           Builds the data panel binary ($(DATA_BIN))."
	@echo "  control        Builds the control panel binary ($(CONTROL_BIN))."
	@echo "  run-data       Builds and runs the data panel binary (requires sudo)."
	@echo "  run-control    Builds and runs the control panel binary (requires sudo)."
	@echo ""
	@echo "Generation & Cleanup Targets:"
	@echo "-----------------------------"
	@echo "  proto          Generates Go code from $(PROTO_SRC) (Protobuf/gRPC)."
	@echo "  ebpf           Runs 'go generate ./...' to compile and embed eBPF object files (.o) into Go code."
	@echo "  clean          Removes all build artifacts ($(BUILD_DIR)) and generated source files."
	@echo "  clean_gen      Removes only generated source files (Protobuf/eBPF code)."
	@echo ""



# --------------------
# Build all panels
# --------------------
build: clean_gen proto ebpf data control
	@echo "-> All binaries built"


# --------------------
# Generate ebpf-go
# --------------------
ebpf:
	@echo "-> Running go generate..."
	go generate ./...

# --------------------
# Build data panel
# --------------------
data:
	@echo "-> Building data panel..."
	go build -o $(DATA_BIN) ./$(CMD_DIR)/data

# --------------------
# Build control panel
# --------------------
control:
	@echo "-> Building control panel..."
	go build -o $(CONTROL_BIN) ./$(CMD_DIR)/control

# --------------------
# Protobuf generation
# --------------------
proto:
	@echo "-> Compiling protobuf files..."
	protoc \
		--go_out=$(PROTO_DIR) --go_opt=paths=source_relative \
		--go-grpc_out=$(PROTO_DIR) --go-grpc_opt=paths=source_relative \
		-I$(PROTO_DIR) $(PROTO_SRC)
	@echo "-> Protobuf code generated"

# --------------------
# Clean generated files
# --------------------
clean_gen:
	@echo "-> Cleaning generated files..."
	rm -f $(GENERATED_FILES)

# --------------------
# Run targets
# --------------------
run-data: data
	@echo "-> Running data panel..."
	sudo $(DATA_BIN)

run-control: control
	@echo "-> Running control panel..."
	$(CONTROL_BIN)

# --------------------
# Full clean
# --------------------
clean:
	@echo "-> Cleaning all build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -f $(GENERATED_FILES)
