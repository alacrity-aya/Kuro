#!/bin/bash

# ==========================================
# 1. Initialize Environment and Variables
# ==========================================
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Default Toggles
RUN_STD=true
RUN_BPF=true
RUN_K8S=true
USE_CACHE=true

VERBOSE=false

EXIT_CODE=0
FAILED_TESTS=()

# ==========================================
# 2. Help Information and Argument Parsing
# ==========================================
usage() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  --verbose     Show verbose output (go test -v)"
    echo "  --only-k8s    Only run Kubernetes integration tests"
    echo "  --only-bpf    Only run BPF tests"
    echo "  --skip-bpf    Skip BPF tests"
    echo "  --skip-k8s    Skip Kubernetes tests"
    echo "  --no-cache    Force run all tests (disable Go cache)"
    echo "  --help        Show this help message"
    exit 0
}

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --verbose) VERBOSE=true ;;
        --only-k8s) RUN_STD=false; RUN_BPF=false; RUN_K8S=true ;;
        --only-bpf) RUN_STD=false; RUN_BPF=true; RUN_K8S=false ;;
        --skip-bpf) RUN_BPF=false ;;
        --skip-k8s) RUN_K8S=false ;;
        --no-cache) USE_CACHE=false ;;
        --help) usage ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

GO_TEST_OPTS=""
if [ "$VERBOSE" = true ]; then
    GO_TEST_OPTS="-v"
fi

if [ "$USE_CACHE" = false ]; then
    GO_TEST_OPTS="$GO_TEST_OPTS -count=1"
fi

# ==========================================
# 3. Utility Functions
# ==========================================
run_task() {
    local DESC=$1
    echo -e "${YELLOW}>>> Running: $DESC...${NC}"
    # Use eval to execute all subsequent arguments as a command
    if eval "${@:2}"; then
        echo -e "${GREEN}Success: $DESC${NC}"
    else
        echo -e "${RED}Failed: $DESC${NC}"
        EXIT_CODE=1
        FAILED_TESTS+=("$DESC")
    fi
}


echo -e "${GREEN}>>> Starting Test Suite...${NC}"

# ==========================================
# 4. Execute Test Logic
# ==========================================

# (1) Standard Tests
if [ "$RUN_STD" = true ]; then
    run_task "Standard Go Tests" \
        "go test $GO_TEST_OPTS ./... -tags=\"!bpf,!k8s\""
fi

# (2) BPF Tests
if [ "$RUN_BPF" = true ]; then
    echo -e "${YELLOW}>>> Preparing BPF tests...${NC}"
    
    echo -e "${YELLOW}>>> BPF tests require root privileges.${NC}"
    if ! sudo -v; then
        echo -e "${RED}Error: Sudo authentication failed. Skipping BPF tests.${NC}"
        EXIT_CODE=1
        FAILED_TESTS+=("BPF Permission Check")
        exit 1
    fi

    BPF_TEMP_DIR=$(mktemp -d)
    PACKAGES=$(go list -tags=bpf ./...)
    FOUND_BPF_TESTS=0

    for PKG in $PACKAGES; do
        SAFE_NAME=${PKG//\//_}
        TEST_BIN="$BPF_TEMP_DIR/$SAFE_NAME.test"

        # Compile package
        OUTPUT=$(go test -c -tags=bpf "$PKG" -o "$TEST_BIN" 2>&1)
        if [ $? -ne 0 ]; then
            if [[ "$OUTPUT" != *"[no test files]"* ]]; then
                echo -e "${RED}BPF Compilation Error in $PKG:${NC}\n$OUTPUT"
                EXIT_CODE=1
                FAILED_TESTS+=("BPF Compile: $PKG")
            fi
            continue
        fi

        if [ -f "$TEST_BIN" ]; then
            FOUND_BPF_TESTS=1
            SHORT_NAME=$(basename "$PKG")
            echo -e "${YELLOW}>>> Running BPF Test: $PKG (Sudo)${NC}"
            
            # 只有在 VERBOSE 为 true 时才传 -test.v
            BPF_RUN_CMD="sudo $TEST_BIN"
            [ "$VERBOSE" = true ] && BPF_RUN_CMD="$BPF_RUN_CMD -test.v"
            [ "$USE_CACHE" = false ] && BPF_RUN_CMD="$BPF_RUN_CMD -test.count=1"

            if eval "$BPF_RUN_CMD"; then
                 echo -e "${GREEN}Success: $SHORT_NAME${NC}"
            else
                 echo -e "${RED}Failed: $SHORT_NAME${NC}"
                 EXIT_CODE=1
                 FAILED_TESTS+=("BPF Run: $SHORT_NAME")
            fi
        fi
    done
    [ $FOUND_BPF_TESTS -eq 0 ] && echo -e "${YELLOW}No BPF tests found.${NC}"
    rm -rf "$BPF_TEMP_DIR"
fi

# (3) K8s Tests
if [ "$RUN_K8S" = true ]; then
    if [ -f "$SCRIPT_DIR/setup_env.sh" ]; then
        run_task "K8s Environment Setup" "bash $SCRIPT_DIR/setup_env.sh"
        if [ $? -eq 0 ]; then
            run_task "K8s Integration Tests" "go test $GO_TEST_OPTS -tags=k8s ./..."
        fi
    else
        echo -e "${RED}Warning: setup_env.sh not found, skipping k8s tests.${NC}"
        [ "$RUN_STD" = false ] && [ "$RUN_BPF" = false ] && EXIT_CODE=1 
    fi
fi

# ==========================================
# 5. Results Summary
# ==========================================
echo -e "\n${GREEN}>>> All tasks completed.${NC}"
if [ $EXIT_CODE -ne 0 ]; then
    echo -e "${RED}Summary of failures:${NC}"
    for FAILED in "${FAILED_TESTS[@]}"; do
        echo -e "${RED}  - $FAILED${NC}"
    done
    exit $EXIT_CODE
else
    echo -e "${GREEN}All test suites passed!${NC}"
    exit 0
fi
