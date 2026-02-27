#!/bin/bash
# run-test-agent-loop.sh - Long Running Test Agent Loop Script
# Usage: ./run-test-agent-loop.sh <iterations>
#
# This script runs the iflow Test Agent in a loop, for each feature:
# 1. Code-level tests (type checking, unit tests, build)
# 2. Browser E2E tests (using MCP tools)

# ============================================
# Configuration
# ============================================
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
WORK_DIR="$PROJECT_ROOT"
FRONTEND_DIR="$WORK_DIR/frontend"
AGENT_HARNESS_DIR="$WORK_DIR/agent-harness"

# Log files
LOG_DIR="$PROJECT_ROOT/logs"
SCREENSHOT_DIR="$LOG_DIR/screenshots"
mkdir -p "$LOG_DIR"
mkdir -p "$SCREENSHOT_DIR"
TEST_LOG="$LOG_DIR/test-loop_$(date +%Y%m%d_%H%M%S).log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Loop counter file (for Ctrl+C recovery)
COUNTER_FILE="$LOG_DIR/.test_loop_counter"
TESTED_FEATURES_FILE="$LOG_DIR/.tested_features"

# ============================================
# Signal handling - Graceful exit
# ============================================
cleanup() {
    echo ""
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW}  Interrupt signal received, saving state...${NC}"
    echo -e "${YELLOW}========================================${NC}"
    
    # Save current progress
    echo "$CURRENT_ITERATION" > "$COUNTER_FILE"
    
    echo -e "${GREEN}State saved. Next run will resume from iteration $((CURRENT_ITERATION + 1)).${NC}"
    echo -e "${CYAN}Log directory: $LOG_DIR${NC}"
    echo -e "${CYAN}Screenshot directory: $SCREENSHOT_DIR${NC}"
    
    # Stop development server
    if [ -n "$DEV_SERVER_PID" ]; then
        echo -e "${YELLOW}Stopping development server (PID: $DEV_SERVER_PID)...${NC}"
        kill "$DEV_SERVER_PID" 2>/dev/null
    fi
    
    exit 0
}

trap cleanup SIGINT SIGTERM

# ============================================
# Help information
# ============================================
show_help() {
    echo "Long Running Test Agent Loop Script"
    echo ""
    echo "Usage: $0 <iterations>"
    echo ""
    echo "Arguments:"
    echo "  iterations    Number of test iterations to execute"
    echo ""
    echo "Examples:"
    echo "  $0 10    # Run 10 test iterations"
    echo "  $0 5     # Run 5 test iterations"
    echo ""
    echo "Options:"
    echo "  -h, --help       Show help information"
    echo "  --resume         Resume from last interruption point"
    echo "  --no-browser     Skip browser tests (run code tests only)"
    echo "  --feature <id>   Test only a specific feature (e.g.: FEAT-015)"
    echo ""
    echo "Log directory: $LOG_DIR"
    echo "Screenshot directory: $SCREENSHOT_DIR"
}

# ============================================
# Get test progress
# ============================================
get_test_progress() {
    local feature_file="$AGENT_HARNESS_DIR/test-feature-list.json"
    if [ -f "$feature_file" ]; then
        if command -v jq &> /dev/null; then
            local total=$(jq '.features | length' "$feature_file" 2>/dev/null || echo "0")
            local passed=$(jq '[.features[] | select(.passes == true)] | length' "$feature_file" 2>/dev/null || echo "0")
            local failed=$(jq '[.features[] | select(.passes == false and .lastTested != null)] | length' "$feature_file" 2>/dev/null || echo "0")
            local pending=$((total - passed - failed))
            echo "✅ $passed passed, ❌ $failed failed, ⏳ $pending pending / total $total"
        else
            echo "(install jq for details)"
        fi
    else
        echo "Test list not found"
    fi
}

# ============================================
# Get next feature to test
# Priority: 1. Previously failed (passes=false, lastTested!=null, retryCount<max)
#           2. Never tested (passes=false, lastTested=null)
# ============================================
get_next_feature() {
    local feature_file="$AGENT_HARNESS_DIR/test-feature-list.json"
    if [ -f "$feature_file" ] && command -v jq &> /dev/null; then
        # First get previously tested but failed features (need retry)
        local failed_feature=$(jq -r '.features[] | select(.passes == false and .lastTested != null and (.retryCount // 0) < 3) | .id' "$feature_file" 2>/dev/null | head -1)
        if [ -n "$failed_feature" ] && [ "$failed_feature" != "null" ]; then
            echo "$failed_feature"
            return
        fi
        # Then get features that have never been tested
        jq -r '.features[] | select(.passes == false and .lastTested == null) | .id' "$feature_file" 2>/dev/null | head -1
    fi
}

# ============================================
# Display session start information
# ============================================
show_session_header() {
    local session=$1
    local total=$2
    local feature_id=$3
    local feature_name=$4
    
    echo ""
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║${NC}  ${BOLD}Test Session $session / $total${NC}"
    echo -e "${BOLD}${CYAN}╠══════════════════════════════════════════════════╣${NC}"
    echo -e "${BOLD}${CYAN}║${NC}  Feature: ${YELLOW}$feature_id${NC}"
    echo -e "${BOLD}${CYAN}║${NC}  Name: $feature_name"
    echo -e "${BOLD}${CYAN}║${NC}  Progress: $(get_test_progress)"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ============================================
# Display session end information
# ============================================
show_session_footer() {
    local duration=$1
    local passed=$2
    local feature_id=$3
    
    echo ""
    if [ "$passed" = "true" ]; then
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${GREEN}  ✅ $feature_id test passed, duration: ${duration} seconds${NC}"
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    else
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${RED}  ❌ $feature_id test failed, duration: ${duration} seconds${NC}"
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    fi
}

# ============================================
# Start development server
# ============================================
start_dev_server() {
    echo -e "${CYAN}  🚀 Starting development server...${NC}"
    
    cd "$FRONTEND_DIR"
    
    # Check node_modules
    if [ ! -d "node_modules" ]; then
        echo -e "${YELLOW}  📦 Installing dependencies...${NC}"
        npm install --silent 2>&1 | tail -5
    fi
    
    # Start development server
    npm run dev > "$LOG_DIR/dev-server.log" 2>&1 &
    DEV_SERVER_PID=$!
    
    # Wait for server to start
    echo -e "${CYAN}  ⏳ Waiting for server to start...${NC}"
    local retries=0
    local max_retries=30
    
    while [ $retries -lt $max_retries ]; do
        if curl -s http://localhost:5173 > /dev/null 2>&1; then
            echo -e "${GREEN}  ✅ Development server started (PID: $DEV_SERVER_PID)${NC}"
            return 0
        fi
        sleep 1
        retries=$((retries + 1))
    done
    
    echo -e "${RED}  ❌ Development server startup timeout${NC}"
    return 1
}

# ============================================
# Stop development server
# ============================================
stop_dev_server() {
    if [ -n "$DEV_SERVER_PID" ]; then
        echo -e "${CYAN}  🛑 Stopping development server...${NC}"
        kill "$DEV_SERVER_PID" 2>/dev/null
        wait "$DEV_SERVER_PID" 2>/dev/null
        DEV_SERVER_PID=""
    fi
}

# ============================================
# Code-level tests
# ============================================
run_code_tests() {
    echo ""
    echo -e "${BOLD}${BLUE}═════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  Phase 1: Code-level Tests${NC}"
    echo -e "${BOLD}${BLUE}═════════════════════════════════════════════════${NC}"
    
    cd "$FRONTEND_DIR"
    
    # 1. Type checking
    echo -e "${CYAN}  🔍 Running TypeScript type check...${NC}"
    if npx tsc --noEmit 2>&1; then
        echo -e "${GREEN}  ✅ Type check passed${NC}"
    else
        echo -e "${RED}  ❌ Type check failed${NC}"
        return 1
    fi
    
    # 2. Unit tests
    echo -e "${CYAN}  🧪 Running unit tests...${NC}"
    if npm run test:run 2>&1; then
        echo -e "${GREEN}  ✅ Unit tests passed${NC}"
    else
        echo -e "${RED}  ❌ Unit tests failed${NC}"
        return 1
    fi
    
    # 3. Build verification
    echo -e "${CYAN}  🏗 Running production build...${NC}"
    if npm run build 2>&1; then
        echo -e "${GREEN}  ✅ Build successful${NC}"
    else
        echo -e "${RED}  ❌ Build failed${NC}"
        return 1
    fi
    
    return 0
}

# ============================================
# Generate iflow prompt
# ============================================
generate_test_prompt() {
    local feature_id=$1
    local feature_name=$2
    local category=$3
    
    cat << PROMPT_EOF
You are the **Test Agent** for the Kuro frontend project. Your task is to execute functional tests, including code tests and browser E2E tests.

## Current Test Task

**Feature ID**: $feature_id
**Feature Name**: $feature_name
**Category**: $category

## Session Startup Flow

### Step 1: Confirm working directory
\`\`\`bash
pwd
\`\`\`

### Step 2: Read test list
Read \`agent-harness/test-feature-list.json\` to understand the detailed test steps for the current feature.

### Step 3: Check development server
The development server should be running at http://localhost:5173, verify if accessible:
\`\`\`bash
curl -s http://localhost:5173 > /dev/null && echo "Server running" || echo "Server not started"
\`\`\`

## Test Phases

### Phase 1: Code-level Tests (external validation completed)

### Phase 2: Browser E2E Tests (your main task)

Use MCP browser tools for the following tests:

1. **browser_navigate** - Navigate to the page under test
2. **browser_wait_for** - Wait for page load
3. **browser_take_screenshot** - Capture key state screenshots
4. **browser_click** - Execute user interactions
5. **browser_evaluate** - Verify page state

**Screenshot Requirements**:
- Save to: logs/screenshots/${feature_id}_\$(date +%Y%m%d_%H%M%S).png
- At least 2: initial state + after key operation

**Verification Points**:
- Page elements render correctly
- Interactive functions work properly
- No console.error errors

## Test Report

After testing, output:
1. Test pass/fail status
2. Issues found (if any)
3. Screenshot file paths

## Update Test List

If test passes:
\`\`\`bash
# Update passes to true in feature_list.json
# Add lastTested timestamp
\`\`\`

If test fails:
\`\`\`bash
# Update lastTested timestamp
# Add failure reason to notes field
\`\`\`

## Important Rules

- Each test step should have clear verification points
- Record issues immediately when found
- Screenshots are required evidence for test pass
- Do not modify the code of the feature under test
PROMPT_EOF
}

# ============================================
# Generate fix agent prompt
# ============================================
generate_fix_prompt() {
    local feature_id=$1
    local feature_name=$2
    local category=$3
    local failure_reason=$4
    
    cat << PROMPT_EOF
You are the **Fix Agent** for the Kuro frontend project. Your task is to fix features that failed testing until tests pass.

## Current Fix Task

**Feature ID**: $feature_id
**Feature Name**: $feature_name
**Category**: $category
**Failure Reason**: $failure_reason

## Fix Flow

### Step 1: Understand feature requirements
Read \\\`agent-harness/test-feature-list.json\\\` to understand the detailed description and test steps for this feature.

### Step 2: Review existing code
Find code files related to this feature and understand the current implementation.

### Step 3: Run tests to verify failure
Run code tests to confirm the failure:
\\\`\\\`\\\`bash
cd frontend
npx tsc --noEmit
npm run test:run
npm run build
\\\`\\\`\\\`

### Step 4: Analyze problem and fix
Based on the failure reason, fix issues in the code. Possible problems include:
- TypeScript type errors
- Unit test failures
- Build errors
- Component rendering issues
- Logic errors

### Step 5: Verify fix
After fixing, run tests again:
\\\`\\\`\\\`bash
cd frontend
npx tsc --noEmit
npm run test:run
npm run build
\\\`\\\`\\\`

### Step 6: Update test list
If fix is successful, update \\\`agent-harness/test-feature-list.json\\\`:
- Change \\\`passes\\\` to \\\`true\\\`
- Add \\\`lastTested\\\` timestamp
- Clear \\\`notes\\\`
- Reset \\\`retryCount\\\` to 0

If fix fails:
- Increment \\\`retryCount\\\`
- Record fix attempts and remaining issues in \\\`notes\\\`

## Important Rules

- Only modify necessary code to fix the problem
- Maintain code style and project consistency
- Must verify tests pass after fixing
- If unable to fix, record detailed problem description
PROMPT_EOF
}

# ============================================
# Update feature retry count
# ============================================
update_retry_count() {
    local feature_id=$1
    local feature_file="$AGENT_HARNESS_DIR/test-feature-list.json"
    
    if [ -f "$feature_file" ] && command -v jq &> /dev/null; then
        local current_count=$(jq -r --arg id "$feature_id" '.features[] | select(.id == $id) | (.retryCount // 0)' "$feature_file" 2>/dev/null)
        local new_count=$((current_count + 1))
        
        # Use jq to update retryCount
        local temp_file=$(mktemp)
        jq --arg id "$feature_id" --argjson count "$new_count" '
            .features = [.features[] | if .id == $id then .retryCount = $count else . end]
        ' "$feature_file" > "$temp_file" && mv "$temp_file" "$feature_file"
    fi
}

# ============================================
# Reset feature retry count
# ============================================
reset_retry_count() {
    local feature_id=$1
    local feature_file="$AGENT_HARNESS_DIR/test-feature-list.json"
    
    if [ -f "$feature_file" ] && command -v jq &> /dev/null; then
        local temp_file=$(mktemp)
        jq --arg id "$feature_id" '
            .features = [.features[] | if .id == $id then .retryCount = 0 else . end]
        ' "$feature_file" > "$temp_file" && mv "$temp_file" "$feature_file"
    fi
}

# ============================================
# Run fix agent
# ============================================
run_fix_agent() {
    local feature_id=$1
    local feature_name=$2
    local category=$3
    local failure_reason=$4
    
    echo ""
    echo -e "${BOLD}${YELLOW}═════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${YELLOW}  Starting Fix Agent${NC}"
    echo -e "${BOLD}${YELLOW}═════════════════════════════════════════════════${NC}"
    
    # Generate fix prompt
    local prompt=$(generate_fix_prompt "$feature_id" "$feature_name" "$category" "$failure_reason")
    
    # Run iflow Fix Agent
    echo -e "${CYAN}  🔧 Starting Fix Agent to repair...${NC}"
    cd "$WORK_DIR"
    
    local fix_log="$LOG_DIR/fix-session_${feature_id}_$(date +%Y%m%d_%H%M%S).log"
    
    iflow -y \
          --max-tokens 100000 \
          --max-turns 100 \
          -p "$prompt" \
          2>&1 | tee "$fix_log"
    
    local iflow_exit_code=${PIPESTATUS[0]}
    
    if [ $iflow_exit_code -ne 0 ]; then
        echo -e "${YELLOW}  ⚠ Fix Agent exited abnormally (code: $iflow_exit_code)${NC}"
    fi
    
    echo -e "${GREEN}  ✅ Fix Agent completed${NC}"
    echo -e "${CYAN}  📝 Fix log: $fix_log${NC}"
}

# ============================================
# Run single test session
# ============================================

run_test_session() {
    local session_num=$1
    local total=$2
    local feature_id=$3
    local no_browser=$4
    
    # Get feature info
    local feature_file="$AGENT_HARNESS_DIR/test-feature-list.json"
    local feature_name=""
    local category=""
    
    if [ -f "$feature_file" ] && command -v jq &> /dev/null; then
        feature_name=$(jq -r --arg id "$feature_id" '.features[] | select(.id == $id) | .name' "$feature_file" 2>/dev/null)
        category=$(jq -r --arg id "$feature_id" '.features[] | select(.id == $id) | .category' "$feature_file" 2>/dev/null)
    fi
    
    if [ -z "$feature_name" ]; then
        echo -e "${RED}Error: Cannot find feature $feature_id${NC}"
        return 1
    fi
    
    # Display session header
    show_session_header "$session_num" "$total" "$feature_id" "$feature_name" | tee -a "$TEST_LOG" > /dev/tty
    
    local session_log="$LOG_DIR/test-session_${session_num}_${feature_id}_$(date +%Y%m%d_%H%M%S).log"
    local start_time=$(date +%s)
    local test_passed="true"
    
    # ============================================
    # Phase 1: Code tests
    # ============================================
    if ! run_code_tests 2>&1 | tee -a "$TEST_LOG"; then
        test_passed="false"
        echo -e "${RED}  ❌ Code tests failed${NC}"
    fi
    
    # ============================================
    # Phase 2: Browser tests
    # ============================================
    if [ "$test_passed" = "true" ] && [ "$no_browser" != "true" ]; then
        echo ""
        echo -e "${BOLD}${BLUE}═════════════════════════════════════════════════${NC}"
        echo -e "${BOLD}${BLUE}  Phase 2: Browser E2E Tests${NC}"
        echo -e "${BOLD}${BLUE}═════════════════════════════════════════════════${NC}"
        
        if [ -z "$DEV_SERVER_PID" ]; then
            start_dev_server || test_passed="false"
        fi
        
        if [ "$test_passed" = "true" ]; then
            local prompt=$(generate_test_prompt "$feature_id" "$feature_name" "$category")
            
            echo -e "${CYAN}  🤖 Starting Test Agent for browser tests...${NC}"
            cd "$WORK_DIR"
            
            iflow -y \
                  --max-tokens 100000 \
                  --max-turns 100 \
                  -p "$prompt" \
                  2>&1 | tee "$session_log"
            
            local iflow_exit_code=${PIPESTATUS[0]}
            
            if [ $iflow_exit_code -ne 0 ]; then
                echo -e "${YELLOW}  ⚠ Test Agent exited abnormally (code: $iflow_exit_code)${NC}"
            fi
            
            # Check if feature passed
            if [ -f "$feature_file" ] && command -v jq &> /dev/null; then
                local feature_passed=$(jq -r --arg id "$feature_id" '.features[] | select(.id == $id) | .passes' "$feature_file" 2>/dev/null)
                if [ "$feature_passed" != "true" ]; then
                    test_passed="false"
                fi
            fi
        fi
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    show_session_footer "$duration" "$test_passed" "$feature_id" | tee -a "$TEST_LOG" > /dev/tty
    
    # ============================================
    # Auto-fix logic
    # ============================================
    if [ "$test_passed" != "true" ]; then
        echo ""
        echo -e "${YELLOW}⚠ Test failure detected, starting fix process...${NC}"
        
        local failure_reason="Test failed"
        if [ -f "$feature_file" ] && command -v jq &> /dev/null; then
            failure_reason=$(jq -r --arg id "$feature_id" \
                '.features[] | select(.id == $id) | .notes // "Test failed, no detailed reason provided"' \
                "$feature_file" 2>/dev/null)
        fi
        
        # Try up to 3 fix attempts
        for attempt in 1 2 3; do
            echo -e "${YELLOW}🔧 Fix attempt #$attempt${NC}"
            
            run_fix_agent "$feature_id" "$feature_name" "$category" "$failure_reason"
            
            echo -e "${CYAN}🔁 Re-validating code tests after fix...${NC}"
            
            if run_code_tests; then
                echo -e "${GREEN}✅ Code tests passed after fix${NC}"
                
                # Check passes status again
                if [ -f "$feature_file" ] && command -v jq &> /dev/null; then
                    local feature_passed_after_fix=$(jq -r --arg id "$feature_id" \
                        '.features[] | select(.id == $id) | .passes' \
                        "$feature_file" 2>/dev/null)
                        
                    if [ "$feature_passed_after_fix" = "true" ]; then
                        echo -e "${GREEN}🎉 Fix successful${NC}"
                        reset_retry_count "$feature_id"
                        test_passed="true"
                        break
                    fi
                fi
            else
                echo -e "${RED}❌ Code tests still failed after fix${NC}"
            fi
        done
        
        if [ "$test_passed" != "true" ]; then
            echo -e "${RED}❌ Still failing after multiple fix attempts${NC}"
            update_retry_count "$feature_id"
        fi
    else
        reset_retry_count "$feature_id"
    fi
    
    echo "$feature_id" >> "$TESTED_FEATURES_FILE"
    
    return 0
}



# ============================================
# Check if all features have been tested
# ============================================
check_all_tested() {
    local feature_file="$AGENT_HARNESS_DIR/test-feature-list.json"
    if [ -f "$feature_file" ] && command -v jq &> /dev/null; then
        local untested=$(jq '[.features[] | select(.passes == false and .lastTested == null)] | length' "$feature_file" 2>/dev/null || echo "1")
        if [ "$untested" -eq 0 ]; then
            return 0  # All features tested
        fi
    fi
    return 1  # Still have untested features
}

# ============================================
# Generate test report
# ============================================
generate_report() {
    local feature_file="$AGENT_HARNESS_DIR/test-feature-list.json"
    
    echo ""
    echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${BLUE}║${NC}           ${BOLD}Test Report${NC}"
    echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
    
    if [ -f "$feature_file" ] && command -v jq &> /dev/null; then
        echo "Feature test status:"
        echo ""
        
        jq -r '.features[] | "\(.id): \(.name) - \(.passes | if . then "✅ passed" else "❌ pending" end)"' "$feature_file" 2>/dev/null | while read line; do
            echo "  $line"
        done
        
        echo ""
        local total=$(jq '.features | length' "$feature_file" 2>/dev/null)
        local passed=$(jq '[.features[] | select(.passes == true)] | length' "$feature_file" 2>/dev/null)
        local percentage=$((passed * 100 / total))
        
        echo "Total: $passed / $total passed ($percentage%)"
    fi
    
    echo ""
    echo "Log file: $TEST_LOG"
    echo "Screenshot directory: $SCREENSHOT_DIR"
    echo ""
}

# ============================================
# Main Program
# ============================================

# Parse Arguments
RESUME=false
NO_BROWSER=false
SINGLE_FEATURE=""

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
        --no-browser)
            NO_BROWSER=true
            shift
            ;;
        --feature)
            SINGLE_FEATURE="$2"
            shift 2
            ;;
        *)
            if [[ "$1" =~ ^[0-9]+$ ]]; then
                ITERATIONS=$1
            fi
            shift
            ;;
    esac
done

# If no iterations specified and not single feature test
if [ -z "$ITERATIONS" ] && [ -z "$SINGLE_FEATURE" ]; then
    echo "Error: Please specify number of iterations or use --feature to specify a single feature"
    show_help
    exit 1
fi

# Single feature test mode
if [ -n "$SINGLE_FEATURE" ]; then
    echo ""
    echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${BLUE}║${NC}     ${BOLD}Kuro Frontend Test - Single Feature Mode${NC}"
    echo -e "${BOLD}${BLUE}╠══════════════════════════════════════════════════╣${NC}"
    echo -e "${BOLD}${BLUE}║${NC}  Feature: $SINGLE_FEATURE"
    echo -e "${BOLD}${BLUE}║${NC}  Browser test: $([ "$NO_BROWSER" = true ] && echo "skip" || echo "enabled")"
    echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
    
    run_test_session 1 1 "$SINGLE_FEATURE" "$NO_BROWSER"
    generate_report
    stop_dev_server
    exit 0
fi

# Resume or initialize counter
if [ "$RESUME" = true ] && [ -f "$COUNTER_FILE" ]; then
    START_ITERATION=$(($(cat "$COUNTER_FILE") + 1))
    echo -e "${GREEN}Resuming from last interruption, starting at iteration $START_ITERATION${NC}"
else
    START_ITERATION=1
    # Clear tested records
    rm -f "$TESTED_FEATURES_FILE"
fi

# Startup information
echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║${NC}     ${BOLD}Kuro Frontend Test - Long Running Test Agent${NC}"
echo -e "${BOLD}${BLUE}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}${BLUE}║${NC}  Iterations: $ITERATIONS"
echo -e "${BOLD}${BLUE}║${NC}  Working directory: $WORK_DIR"
echo -e "${BOLD}${BLUE}║${NC}  Log directory: $LOG_DIR"
echo -e "${BOLD}${BLUE}║${NC}  Screenshot directory: $SCREENSHOT_DIR"
echo -e "${BOLD}${BLUE}║${NC}  Browser test: $([ "$NO_BROWSER" = true ] && echo "skip" || echo "enabled")"
echo -e "${BOLD}${BLUE}║${NC}  Current progress: $(get_test_progress)"
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# Main loop
CURRENT_ITERATION=$START_ITERATION
for i in $(seq "$START_ITERATION" "$ITERATIONS"); do
    CURRENT_ITERATION=$i
    
    # Get next feature to test
    FEATURE_ID=$(get_next_feature)
    
    if [ -z "$FEATURE_ID" ]; then
        echo ""
        echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}  🎉 All features tested! Ending loop early.${NC}"
        echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
        break
    fi
    
    run_test_session "$i" "$ITERATIONS" "$FEATURE_ID" "$NO_BROWSER"
    
    # If not the last iteration, show separator
    if [ "$i" -lt "$ITERATIONS" ]; then
        echo ""
        echo -e "${YELLOW}>>> Waiting 5 seconds before next test... (Ctrl+C to safely interrupt)${NC}"
        sleep 5
    fi
done

# Stop development server
stop_dev_server

# Generate report
generate_report

# End
echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║${NC}     ${BOLD}Test loop completed!${NC}"
echo -e "${BOLD}${GREEN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}${GREEN}║${NC}  Total executions: $((CURRENT_ITERATION - START_ITERATION + 1))"
echo -e "${BOLD}${GREEN}║${NC}  Final progress: $(get_test_progress)"
echo -e "${BOLD}${GREEN}║${NC}  Log directory: $LOG_DIR"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# Clean up counter file
rm -f "$COUNTER_FILE"

# Display final report
cat "$TEST_LOG" 2>/dev/null | tail -50
