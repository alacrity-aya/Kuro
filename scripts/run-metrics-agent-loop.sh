#!/bin/bash
# run-metrics-agent-loop.sh - Run Metrics page development in a loop
# Usage: ./run-metrics-agent-loop.sh <count>

# ============================================
# Configuration
# ============================================
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
WORK_DIR="$PROJECT_ROOT"
FRONTEND_DIR="$WORK_DIR/frontend"

# Use metrics feature list
FEATURE_FILE="$WORK_DIR/agent-harness/metrics-feature-list.json"

# Log files
LOG_DIR="$PROJECT_ROOT/logs"
mkdir -p "$LOG_DIR"
MAIN_LOG="$LOG_DIR/metrics_loop_$(date +%Y%m%d_%H%M%S).log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Loop counter file
COUNTER_FILE="$LOG_DIR/.metrics_loop_counter"

# ============================================
# Signal Handling - Graceful Exit
# ============================================
cleanup() {
    echo ""
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW}  Interrupt signal received, saving state...${NC}"
    echo -e "${YELLOW}========================================${NC}"
    
    echo "$CURRENT_ITERATION" > "$COUNTER_FILE"
    
    echo -e "${GREEN}State saved. Next run will continue from iteration $((CURRENT_ITERATION + 1)).${NC}"
    echo -e "${CYAN}Log directory: $LOG_DIR${NC}"
    exit 0
}

trap cleanup SIGINT SIGTERM

# ============================================
# Help Information
# ============================================
show_help() {
    echo "Metrics Page Development Loop Script"
    echo ""
    echo "Usage: $0 <loop_count>"
    echo ""
    echo "Arguments:"
    echo "  loop_count    Number of times to run iflow"
    echo ""
    echo "Examples:"
    echo "  $0 10    # Run 10 times"
    echo "  $0 5     # Run 5 times"
    echo ""
    echo "Options:"
    echo "  -h, --help    Show help information"
    echo "  --resume      Resume from last interruption point"
    echo "  --no-verify   Skip test verification"
    echo ""
    echo "Feature list: agent-harness/metrics-feature-list.json"
    echo "Log directory: $LOG_DIR"
}

# ============================================
# Get feature progress
# ============================================
get_feature_progress() {
    if [ -f "$FEATURE_FILE" ]; then
        if command -v jq &> /dev/null; then
            local total=$(jq '.features | length' "$FEATURE_FILE" 2>/dev/null || echo "0")
            local complete=$(jq '[.features[] | select(.passes == true)] | length' "$FEATURE_FILE" 2>/dev/null || echo "0")
            local incomplete=$((total - complete))
            echo "$complete/$total completed, $incomplete remaining"
        else
            echo "(install jq for details)"
        fi
    else
        echo "Not initialized"
    fi
}

# ============================================
# Display session start information
# ============================================
show_session_header() {
    local session=$1
    local total=$2
    
    echo ""
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║${NC}  ${BOLD}Metrics Development Session $session / $total${NC}"
    echo -e "${BOLD}${CYAN}╠══════════════════════════════════════════════════╣${NC}"
    echo -e "${BOLD}${CYAN}║${NC}  Progress: $(get_feature_progress)"
    echo -e "${BOLD}${CYAN}║${NC}  Directory: $WORK_DIR"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ============================================
# Display session end information
# ============================================
show_session_footer() {
    local duration=$1
    local verified=$2
    
    echo ""
    if [ "$verified" = "true" ]; then
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${GREEN}  ✅ Session completed and verified, duration: ${duration}s${NC}"
        echo -e "${GREEN}  Progress: $(get_feature_progress)${NC}"
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    else
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${RED}  ❌ Session completed but verification failed, duration: ${duration}s${NC}"
        echo -e "${RED}  Commit has been rolled back${NC}"
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    fi
}

# ============================================
# Verify build
# ============================================
verify_build() {
    echo -e "${CYAN}  🔍 Running build verification...${NC}"
    
    cd "$FRONTEND_DIR"
    
    if [ ! -d "node_modules" ]; then
        echo -e "${YELLOW}  📦 Installing dependencies...${NC}"
        npm install --silent 2>&1 | tail -5
    fi
    
    echo -e "${CYAN}  🏗 Executing npm run build...${NC}"
    if npm run build 2>&1; then
        echo -e "${GREEN}  ✅ Build successful${NC}"
        return 0
    else
        echo -e "${RED}  ❌ Build failed${NC}"
        return 1
    fi
}

# ============================================
# Rollback last commit
# ============================================
rollback_last_commit() {
    echo -e "${YELLOW}  ⏪ Rolling back last commit...${NC}"
    cd "$WORK_DIR"
    git reset --hard HEAD~1 2>/dev/null
    echo -e "${YELLOW}  Rolled back${NC}"
}

# ============================================
# Reset last completed feature
# ============================================
reset_last_feature() {
    if [ -f "$FEATURE_FILE" ] && command -v jq &> /dev/null; then
        jq '(.features | map(select(.passes == true)) | last | .passes = false) // empty | . as $last | .features |= map(if .id == $last.id then .passes = false else . end)' "$FEATURE_FILE" > "${FEATURE_FILE}.tmp" 2>/dev/null
        if [ -s "${FEATURE_FILE}.tmp" ]; then
            mv "${FEATURE_FILE}.tmp" "$FEATURE_FILE"
            echo -e "${YELLOW}  Reset last completed feature in metrics-feature-list.json${NC}"
        else
            rm -f "${FEATURE_FILE}.tmp"
        fi
    fi
}

# ============================================
# Generate iflow prompt
# ============================================
generate_prompt() {
    cat << 'PROMPT_EOF'
You are the Coding Agent, responsible for developing the Kuro frontend Metrics monitoring page.

## ⚠️ Key Requirements: Must pass tests before completion

**Before marking any feature as complete, you must perform the following verification steps:**

1. Run build: `cd frontend && npm run build`
2. Ensure build succeeds without any errors
3. Only proceed if build is successful

**If build fails:**
- Fix errors and rebuild
- Do not mark feature as complete
- Do not commit code

## Important Constraints

### ⚠️ Backend Constraints
- **Do not modify backend code**
- For all places requiring backend API, use mock functions from `frontend/src/api/mock.ts`
- Clearly annotate in code comments: `// TODO: Requires backend API - GET /api/v1/metrics/xxx`

## Startup Routine Check (Must Execute)

1. Confirm working directory:
   ```bash
   pwd
   ```

2. Read feature list:
   ```bash
   cat agent-harness/metrics-feature-list.json
   ```

3. Read development guide:
   ```bash
   cat agent-harness/metrics-agent-prompt.md
   ```

4. View existing metrics components:
   ```bash
   ls -la frontend/src/components/metrics/
   cat frontend/src/api/mock.ts | grep -A 30 "Mock Metrics"
   ```

5. View recent git commits:
   ```bash
   git log --oneline -5
   ```

## Workflow

1. **Select Feature**: Choose the highest priority incomplete feature from agent-harness/metrics-feature-list.json (passes: false)

2. **Read Guide**: Refer to implementation guide in agent-harness/metrics-agent-prompt.md

3. **Implement Feature**: Write code, keep it simple and focused

4. **⚠️ Test Verification (Must Pass)**:
   ```bash
   cd frontend
   npm install  # If needed
   npm run build  # Must succeed!
   ```

5. **Commit Code** (Only after tests pass):
   ```bash
   git add .
   git commit -m "feat(metrics): [feature description] (METRICS-xxx)"
   ```

6. **Update Feature List**: Only modify the passes field of the corresponding feature to true

## Recommended Development Order

Implement features in the following order:

### Phase 1: Infrastructure
- METRICS-013: Mock Metrics API
- METRICS-014: useMetrics Hook

### Phase 2: Page Layout
- METRICS-001: Metrics Dashboard Page Layout
- METRICS-009: Time Range Selector
- METRICS-010: Auto Refresh
- METRICS-008: Topology Selector

### Phase 3: Chart Components
- METRICS-002: Topology Summary Cards
- METRICS-003: Bandwidth Overview Chart
- METRICS-004: Latency Distribution Chart
- METRICS-005: Packet Loss Gauge Panel

### Phase 4: Tables and Integration
- METRICS-006: Node Metrics Table
- METRICS-007: Link Metrics Table
- METRICS-012: Alerts Panel
- METRICS-015: Metrics Page Integration

## Important Rules

- 🚫 **Build failure = Feature not complete**
- Each session handles only one feature
- Never delete or modify feature descriptions
- All APIs use mock data
- Ensure clean environment before leaving

## Session End

Output session summary:
1. Work completed
2. Build verification result (success/failure)
3. Updated file list
4. Next step suggestions
PROMPT_EOF
}

# ============================================
# Run single iflow session
# ============================================
run_iflow_session() {
    local session_num=$1
    local total=$2
    local no_verify=$3
    
    show_session_header "$session_num" "$total" | tee -a "$MAIN_LOG" > /dev/tty
    
    local session_log="$LOG_DIR/metrics_session_${session_num}_$(date +%Y%m%d_%H%M%S).log"
    local prompt=$(generate_prompt)
    
    cd "$WORK_DIR"
    
    local start_time=$(date +%s)
    
    iflow -y \
          --max-tokens 100000 \
          --max-turns 50 \
          --thinking \
          -p "$prompt" \
          2>&1 | tee "$session_log"
    
    local exit_code=${PIPESTATUS[0]}
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    local verified="true"
    
    if [ "$no_verify" != "true" ]; then
        echo ""
        echo -e "${BOLD}${BLUE}═════════════════════════════════════════════════${NC}"
        echo -e "${BOLD}${BLUE}  Verification Phase${NC}"
        echo -e "${BOLD}${BLUE}═════════════════════════════════════════════════${NC}"
        
        if ! verify_build; then
            verified="false"
            echo ""
            echo -e "${RED}  ❌ Verification failed, rolling back changes...${NC}"
            rollback_last_commit
            reset_last_feature
        fi
    fi
    
    show_session_footer "$duration" "$verified" | tee -a "$MAIN_LOG" > /dev/tty
    
    return 0
}

# ============================================
# Check if all features are completed
# ============================================
check_completion() {
    if [ -f "$FEATURE_FILE" ] && command -v jq &> /dev/null; then
        local incomplete=$(jq '[.features[] | select(.passes == false)] | length' "$FEATURE_FILE" 2>/dev/null || echo "1")
        if [ "$incomplete" -eq 0 ]; then
            return 0
        fi
    fi
    return 1
}

# ============================================
# Main Program
# ============================================

RESUME=false
NO_VERIFY=false
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        --resume)
            RESUME=true
            shift
            ;;
        --no-verify)
            NO_VERIFY=true
            shift
            ;;
        *)
            if [[ "$1" =~ ^[0-9]+$ ]]; then
                ITERATIONS=$1
            fi
            shift
            ;;
    esac
done

if [ -z "$ITERATIONS" ]; then
    echo "Error: Please specify loop count"
    show_help
    exit 1
fi

if [ "$RESUME" = true ] && [ -f "$COUNTER_FILE" ]; then
    START_ITERATION=$(($(cat "$COUNTER_FILE") + 1))
    echo -e "${GREEN}Resuming from last interruption, starting from iteration $START_ITERATION${NC}"
else
    START_ITERATION=1
fi

echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║${NC}     ${BOLD}Kuro Metrics Page Development - Long Running Agent${NC}"
echo -e "${BOLD}${BLUE}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}${BLUE}║${NC}  Loop count: $ITERATIONS"
echo -e "${BOLD}${BLUE}║${NC}  Working directory: $WORK_DIR"
echo -e "${BOLD}${BLUE}║${NC}  Feature list: agent-harness/metrics-feature-list.json"
echo -e "${BOLD}${BLUE}║${NC}  Log directory: $LOG_DIR"
echo -e "${BOLD}${BLUE}║${NC}  Verification mode: $([ "$NO_VERIFY" = true ] && echo "disabled" || echo "enabled")"
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════╝${NC}"
echo ""

CURRENT_ITERATION=$START_ITERATION
for i in $(seq "$START_ITERATION" "$ITERATIONS"); do
    CURRENT_ITERATION=$i
    
    run_iflow_session "$i" "$ITERATIONS" "$NO_VERIFY"
    
    if check_completion; then
        echo ""
        echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}  🎉 All Metrics features completed! Ending loop early.${NC}"
        echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
        rm -f "$COUNTER_FILE"
        exit 0
    fi
    
    if [ "$i" -lt "$ITERATIONS" ]; then
        echo ""
        echo -e "${YELLOW}>>> Waiting 3 seconds before next session... (Ctrl+C to safely interrupt)${NC}"
        sleep 3
    fi
done

echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║${NC}     ${BOLD}Loop execution completed!${NC}"
echo -e "${BOLD}${GREEN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}${GREEN}║${NC}  Total executions: $ITERATIONS"
echo -e "${BOLD}${GREEN}║${NC}  Final progress: $(get_feature_progress)"
echo -e "${BOLD}${GREEN}║${NC}  Log directory: $LOG_DIR"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

rm -f "$COUNTER_FILE"
