#!/bin/bash

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

EXIT_CODE=0
FAILED_TESTS=()

run_task() {
    local DESC=$1
    echo -e "${YELLOW}>>> Running: $DESC...${NC}"
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
# 1. Run Standard Tests (Exclude bpf and k8s)
# ==========================================
# Added -v for verbosity
run_task "Standard Go Tests" \
    "go test ./... -v -tags=\"!bpf,!k8s\""

# ==========================================
# 2. Run BPF Tests (Compile per package -> Run with Sudo)
# ==========================================
echo -e "${YELLOW}>>> Preparing BPF tests...${NC}"

BPF_TEMP_DIR=$(mktemp -d)
echo "Temporary test dir: $BPF_TEMP_DIR"

# Get all packages
PACKAGES=$(go list -tags=bpf ./...)

FOUND_BPF_TESTS=0

for PKG in $PACKAGES; do
    # Generate unique filename: example.com/kuro/cmd/agent -> example.com_kuro_cmd_agent.test
    # Replace / with _
    SAFE_NAME=${PKG//\//_}
    TEST_BIN="$BPF_TEMP_DIR/$SAFE_NAME.test"

    # Attempt to compile a single package
    # 2>&1 > /dev/null hides "no test files" messages
    # But we capture output to show actual compile errors
    OUTPUT=$(go test -c -tags=bpf "$PKG" -o "$TEST_BIN" 2>&1)
    COMPILE_RET=$?

    if [ $COMPILE_RET -ne 0 ]; then
        # If it's not a "no test files" error, it's a real compilation error
        if [[ "$OUTPUT" != *"[no test files]"* ]]; then
            echo -e "${RED}BPF Compilation Error in $PKG:${NC}"
            echo "$OUTPUT"
            EXIT_CODE=1
            FAILED_TESTS+=("BPF Compile: $PKG")
        fi
        continue
    fi

    # If compilation succeeded and file exists (package has BPF tests)
    if [ -f "$TEST_BIN" ]; then
        FOUND_BPF_TESTS=1
        SHORT_NAME=$(basename "$PKG") # Show short name for readability
        
        echo -e "${YELLOW}>>> Running BPF Test: $PKG (Sudo)${NC}"
        
        # Note: Compiled binaries use -test.v instead of -v
        if sudo "$TEST_BIN" -test.v; then
             echo -e "${GREEN}Success: $SHORT_NAME${NC}"
        else
             echo -e "${RED}Failed: $SHORT_NAME${NC}"
             EXIT_CODE=1
             FAILED_TESTS+=("BPF Run: $SHORT_NAME")
        fi
    fi
done

if [ $FOUND_BPF_TESTS -eq 0 ]; then
    echo -e "${YELLOW}No specific BPF tests executed.${NC}"
fi

# Clean up
rm -rf "$BPF_TEMP_DIR"

# ==========================================
# 3. Run K8s Tests (Setup Environment First)
# ==========================================
if [ -f "$SCRIPT_DIR/setup_env.sh" ]; then
    run_task "K8s Environment Setup" "bash $SCRIPT_DIR/setup_env.sh"
    
    if [ $? -eq 0 ]; then
        # Added -v for verbosity
        run_task "K8s Integration Tests" "go test -v -tags=k8s ./..."
    fi
else
    echo -e "${RED}Warning: setup_env.sh not found, skipping k8s tests.${NC}"
fi

# ==========================================
# Results Summary
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
