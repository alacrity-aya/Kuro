# ------------------------------------------------------------------------------
# Makefile for kuro eBPF project
# Implements 'build' and 'run' targets for code generation and execution.
# ------------------------------------------------------------------------------

# Define project variables
BINARY_NAME := kuro
GEN_DIR := gen
BUILD_DIR := bin

# Define the list of generated files to be cleaned
GENERATED_FILES := $(GEN_DIR)/tc_bpfeb.go $(GEN_DIR)/tc_bpfeb.o $(GEN_DIR)/tc_bpfel.go $(GEN_DIR)/tc_bpfel.o

# Define phonies targets
.PHONY: all build run clean clean_gen

# Default target: build
all: build

# --------------------
# 1. BUILD Target
# Executes cleanup, code generation, and final compilation.
# --------------------
build: clean_gen
	@echo "-> Running go generate..."
	go generate ./...
	@echo "-> Running go build..."
	go build -o $(BUILD_DIR)/$(BINARY_NAME)

# Helper target: Cleans generated files
clean_gen:
	@echo "-> Cleaning generated files in $(GEN_DIR)/"
	rm -f $(GENERATED_FILES)

# --------------------
# 2. RUN Target
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
