#!/bin/bash

# ==========================================
# 1. Initialize Environment
# ==========================================
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

BENCH_TIME="10s"     
BENCH_FILTER="."     
BUILD_TAGS="bpf,benchmark" 

EXIT_CODE=0

# ==========================================
# 2. Argument Parsing
# ==========================================
usage() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  --time <duration>   Set benchmark duration (e.g., 5s, 1m). Default: 10s"
    echo "  --filter <regex>    Run only benchmarks matching regex. Default: ."
    echo "  --help              Show this help message"
    exit 0
}

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --time) BENCH_TIME="$2"; shift ;;
        --filter) BENCH_FILTER="$2"; shift ;;
        --help) usage ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
    shift
done

# ==========================================
# 3. Execution Logic
# ==========================================

echo -e "${GREEN}>>> Starting Benchmark Suite...${NC}"

echo -e "${YELLOW}>>> Benchmarks require root privileges to load eBPF/TC.${NC}"
if ! sudo -v; then
    echo -e "${RED}Error: Sudo authentication failed.${NC}"
    exit 1
fi

echo -e "${YELLOW}>>> Compiling Benchmark Binary (tags: $BUILD_TAGS)...${NC}"
TEMP_BIN=$(mktemp)
trap 'rm -f $TEMP_BIN' EXIT

if go test -c -tags="$BUILD_TAGS" -o "$TEMP_BIN" ./test; then
    echo -e "${GREEN}Compilation Success.${NC}"
else
    echo -e "${RED}Compilation Failed!${NC}"
    exit 1
fi

echo -e "${YELLOW}>>> Running Benchmarks (Duration: $BENCH_TIME)...${NC}"
echo -e "${YELLOW}-----------------------------------------------------${NC}"

ABS_BENCH_BIN=$(readlink -f "$TEMP_BIN")

cd "$PROJECT_ROOT/test" || exit 1

if sudo "$ABS_BENCH_BIN" \
    -test.run="^$" \
    -test.bench="$BENCH_FILTER" \
    -test.benchtime="$BENCH_TIME" \
    -test.count=1 \
    -test.v; then
    
    echo -e "${YELLOW}-----------------------------------------------------${NC}"
    echo -e "${GREEN}>>> Benchmark Completed Successfully.${NC}"
else
    echo -e "${RED}>>> Benchmark Failed or Crashed.${NC}"
    EXIT_CODE=1
fi

cd "$PROJECT_ROOT"

exit $EXIT_CODE
