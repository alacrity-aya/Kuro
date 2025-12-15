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

PROTO_SRC := $(PROTO_DIR)/kuro.proto

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
	sudo $(CONTROL_BIN)

# --------------------
# Full clean
# --------------------
clean:
	@echo "-> Cleaning all build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -f $(GENERATED_FILES)
