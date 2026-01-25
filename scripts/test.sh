#!/bin/bash

# ==========================================
# 1. Environment Initialization
# ==========================================
set -e # Exit immediately if a command exits with a non-zero status

# Get project root directory regardless of where the script is executed
CURRENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ "$(basename "$CURRENT_DIR")" == "scripts" ]]; then
    PROJECT_ROOT="$(dirname "$CURRENT_DIR")"
else
    PROJECT_ROOT="$CURRENT_DIR"
fi
cd "$PROJECT_ROOT"

# Color Definitions
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default States
MODE_STD=false
MODE_BPF=false
MODE_K8S=false
MODE_BENCH=false
VERBOSE=false
NO_CACHE=false

# Go Test Base Parameters
GO_FLAGS=""
TEST_ARGS=""

# ==========================================
# 2. Argument Parsing
# ==========================================
usage() {
    echo -e "${CYAN}Kuro Unified Test Runner${NC}"
    echo "Usage: ./run.sh [targets] [options]"
    echo ""
    echo "Targets:"
    echo "  -std         Run standard unit tests (non-root)"
    echo "  -bpf         Run eBPF integration tests (requires sudo)"
    echo "  -k8s         Run K8s integration tests (requires setup)"
    echo "  -benchmark   Run benchmarks (requires sudo)"
    echo "  -all         Run ALL tests (Std + BPF + K8s + Benchmark)"
    echo ""
    echo "Options:"
    echo "  --verbose    Show verbose output (-v)"
    echo "  --no-cache   Disable Go test cache (-count=1)"
    echo "  --help       Show this help message"
    exit 0
}

# If no arguments provided, show usage
if [[ "$#" -eq 0 ]]; then
    usage
fi

while [[ "$#" -gt 0 ]]; do
    case $1 in
        -std)       MODE_STD=true ;;
        -bpf)       MODE_BPF=true ;;
        -k8s)       MODE_K8S=true ;;
        -benchmark) MODE_BENCH=true ;;
        -all)       MODE_STD=true; MODE_BPF=true; MODE_K8S=true; MODE_BENCH=true ;;
        --verbose)  VERBOSE=true ;;
        --no-cache) NO_CACHE=true ;;
        --help)     usage ;;
        *)          echo -e "${RED}Unknown parameter: $1${NC}"; exit 1 ;;
    esac
    shift
done

# Build Go arguments
if [ "$VERBOSE" = true ]; then
    TEST_ARGS="$TEST_ARGS -test.v"
    GO_FLAGS="$GO_FLAGS -v"
fi

if [ "$NO_CACHE" = true ]; then
    TEST_ARGS="$TEST_ARGS -test.count=1"
    GO_FLAGS="$GO_FLAGS -count=1"
fi

# ==========================================
# 3. Helper Functions
# ==========================================

ensure_root() {
    echo -e "${YELLOW}>>> This step requires root privileges. Checking sudo...${NC}"
    if ! sudo -v; then
        echo -e "${RED}Error: Sudo authentication failed.${NC}"
        exit 1
    fi
}

run_std_tests() {
    echo -e "\n${CYAN}========================================${NC}"
    echo -e "${CYAN}>>> Running Standard Unit Tests...${NC}"
    echo -e "${CYAN}========================================${NC}"
    
    # Exclude tags that require special environments
    if go test $GO_FLAGS ./... -tags="!bpf,!k8s,!benchmark"; then
        echo -e "${GREEN}>>> Standard Tests Passed.${NC}"
    else
        echo -e "${RED}>>> Standard Tests Failed.${NC}"
        exit 1
    fi
}

run_bpf_tests() {
    echo -e "\n${CYAN}========================================${NC}"
    echo -e "${CYAN}>>> Running eBPF Integration Tests...${NC}"
    echo -e "${CYAN}========================================${NC}"
    
    ensure_root

    # Create temporary directory for compiled test binaries
    TEMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TEMP_DIR"' EXIT

    # Find packages with the 'bpf' tag
    PACKAGES=$(go list -tags=bpf ./...)
    
    if [ -z "$PACKAGES" ]; then
        echo -e "${YELLOW}No packages with 'bpf' tag found.${NC}"
        return
    fi

    for PKG in $PACKAGES; do
        SAFE_NAME=$(basename "$PKG")
        TEST_BIN="$TEMP_DIR/$SAFE_NAME.test"

        echo -e "${YELLOW}Compiling $PKG...${NC}"
        # Compile test binary (Compile as current user to avoid sudo polluting go cache)
        if go test -c -tags=bpf "$PKG" -o "$TEST_BIN"; then
            echo -e "${YELLOW}Running $PKG (with sudo)...${NC}"
            # Run the binary (Root privileges)
            # Note: eval or direct variable expansion handles TEST_ARGS properly
            if sudo "$TEST_BIN" $TEST_ARGS; then
                echo -e "${GREEN}>>> $SAFE_NAME Passed.${NC}"
            else
                echo -e "${RED}>>> $SAFE_NAME Failed.${NC}"
                exit 1
            fi
        else
            echo -e "${RED}Compilation Failed for $PKG${NC}"
            exit 1
        fi
    done
}

run_k8s_tests() {
    echo -e "\n${CYAN}========================================${NC}"
    echo -e "${CYAN}>>> Running Kubernetes Integration Tests...${NC}"
    echo -e "${CYAN}========================================${NC}"

    SETUP_SCRIPT="$PROJECT_ROOT/scripts/setup_env.sh"
    
    if [ -f "$SETUP_SCRIPT" ]; then
        echo -e "${YELLOW}Setting up K8s Environment...${NC}"
        # Assume setup_env.sh handles environment preparation
        bash "$SETUP_SCRIPT"
        
        echo -e "${YELLOW}Running K8s Tests...${NC}"
        if go test $GO_FLAGS -tags=k8s ./...; then
            echo -e "${GREEN}>>> K8s Tests Passed.${NC}"
        else
            echo -e "${RED}>>> K8s Tests Failed.${NC}"
            exit 1
        fi
    else
        echo -e "${RED}Warning: scripts/setup_env.sh not found. Skipping K8s tests.${NC}"
        exit 1
    fi
}

run_benchmarks() {
    echo -e "\n${CYAN}========================================${NC}"
    echo -e "${CYAN}>>> Running Benchmarks...${NC}"
    echo -e "${CYAN}========================================${NC}"

    ensure_root
    
    TEMP_BIN=$(mktemp)
    trap 'rm -f "$TEMP_BIN"' EXIT

    echo -e "${YELLOW}Compiling Benchmarks...${NC}"
    # Compile Benchmark binary
    if go test -c -tags="bpf,benchmark" -o "$TEMP_BIN" ./test; then
        echo -e "${YELLOW}Executing Benchmarks...${NC}"
        
        # Construct Benchmark arguments
        BENCH_ARGS="-test.run=^$ -test.bench=."
        [ "$VERBOSE" = true ] && BENCH_ARGS="$BENCH_ARGS -test.v"
        # Benchmarks are count=1 by default, but we pass NO_CACHE if specified
        [ "$NO_CACHE" = true ] && BENCH_ARGS="$BENCH_ARGS -test.count=1"

        if sudo "$TEMP_BIN" $BENCH_ARGS; then
            echo -e "${GREEN}>>> Benchmarks Completed.${NC}"
        else
            echo -e "${RED}>>> Benchmarks Failed.${NC}"
            exit 1
        fi
    else
        echo -e "${RED}Benchmark Compilation Failed.${NC}"
        exit 1
    fi
}

# ==========================================
# 4. Execution Flow
# ==========================================

# 1. Standard Tests
if [ "$MODE_STD" = true ]; then
    run_std_tests
fi

# 2. BPF Tests
if [ "$MODE_BPF" = true ]; then
    run_bpf_tests
fi

# 3. K8s Tests
if [ "$MODE_K8S" = true ]; then
    run_k8s_tests
fi

# 4. Benchmarks
if [ "$MODE_BENCH" = true ]; then
    run_benchmarks
fi

echo -e "\n${GREEN}>>> All requested tasks finished successfully.${NC}"
