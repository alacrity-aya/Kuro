#!/bin/bash

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

EXIT_CODE=0
FAILED_TESTS=()

echo -e "${GREEN}>>> Starting all tests...${NC}"

echo -e "${YELLOW}Running standard Go tests...${NC}"
if ! go test $(go list ./... | grep -v "/test$") -v; then
    echo -e "${RED}Standard tests failed!${NC}"
    EXIT_CODE=1
    FAILED_TESTS+=("Standard Go Tests")
fi

BPF_TEST_FILES=(
    "./test/bpf_test.go"
    # "./test/network_test.go" 
)

echo -e "${YELLOW}Processing Sudo-required tests...${NC}"

for TEST_FILE in "${BPF_TEST_FILES[@]}"; do
    if [ -f "$TEST_FILE" ]; then
        TEST_NAME=$(basename "$TEST_FILE")
        TEMP_BIN="/tmp/test_runner_${TEST_NAME}"

        echo -e "${YELLOW}Compiling $TEST_NAME...${NC}"
        
        if go test -c "$TEST_FILE" -o "$TEMP_BIN"; then
            echo -e "${GREEN}Running $TEST_NAME with sudo...${NC}"
            
            if sudo "$TEMP_BIN" -test.v; then
                echo -e "${GREEN}Successfully passed: $TEST_NAME${NC}"
            else
                echo -e "${RED}Failed: $TEST_NAME${NC}"
                EXIT_CODE=1
                FAILED_TESTS+=("$TEST_NAME (Execution)")
            fi
            
            rm "$TEMP_BIN"
        else
            echo -e "${RED}Error: Failed to compile $TEST_FILE${NC}"
            EXIT_CODE=1
            FAILED_TESTS+=("$TEST_NAME (Compilation)")
        fi
    else
        echo -e "${RED}Warning: Test file not found: $TEST_FILE${NC}"
    fi
done

echo -e "\n${GREEN}>>> All tests completed.${NC}"

if [ $EXIT_CODE -ne 0 ]; then
    echo -e "${RED}Some tests failed:${NC}"
    for FAILED in "${FAILED_TESTS[@]}"; do
        echo -e "${RED}  - $FAILED${NC}"
    done
    exit $EXIT_CODE
else
    echo -e "${GREEN}All tests passed successfully!${NC}"
    exit 0
fi
