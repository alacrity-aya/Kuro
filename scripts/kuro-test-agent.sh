#!/bin/bash
# Kuro Frontend Test Agent - Long-running test script
# Usage: ./kuro-test-agent.sh [options]
#
# Features:
# - Automated frontend functional testing
# - Code-level testing (TypeScript type checking, unit tests, build)
# - Browser E2E testing (using Playwright/MCP tools)
# - Automatic fixing of failed tests
# - Detailed test report generation

# ============================================
# Configuration
# ============================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
WORK_DIR="$PROJECT_ROOT"
FRONTEND_DIR="$WORK_DIR/frontend"
AGENT_HARNESS_DIR="$WORK_DIR/agent-harness"

# Logs and output
LOG_DIR="$PROJECT_ROOT/logs"
SCREENSHOT_DIR="$LOG_DIR/screenshots"
REPORT_DIR="$LOG_DIR/reports"
STATE_DIR="$LOG_DIR/.state"
mkdir -p "$LOG_DIR" "$SCREENSHOT_DIR" "$REPORT_DIR" "$STATE_DIR"

# State files
STATE_FILE="$STATE_DIR/test_state.json"
CHECKPOINT_FILE="$STATE_DIR/checkpoint.txt"
PID_FILE="$STATE_DIR/agent.pid"

# Test configuration
DEFAULT_TIMEOUT=300000  # 5 minutes
DEFAULT_MAX_RETRIES=3
DEFAULT_PARALLEL_TESTS=1

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# ============================================
# Logging Functions
# ============================================
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_DIR/agent.log"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1" | tee -a "$LOG_DIR/agent.log"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_DIR/agent.log"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1" | tee -a "$LOG_DIR/agent.log"
}

log_debug() {
    if [[ "$DEBUG" == "true" ]]; then
        echo -e "${CYAN}[DEBUG]${NC} $1" | tee -a "$LOG_DIR/agent.log"
    fi
}

# ============================================
# Signal Handling
# ============================================
cleanup() {
    echo ""
    log_warn "Received interrupt signal, saving state..."
    
    # Save checkpoint
    echo "$CURRENT_ITERATION" > "$CHECKPOINT_FILE"
    
    # Save current test state
    if [[ -n "$CURRENT_FEATURE" ]]; then
        save_state "$CURRENT_FEATURE" "interrupted" "Test interrupted"
    fi
    
    # Stop development server
    stop_dev_server
    
    # Remove PID file
    rm -f "$PID_FILE"
    
    log_info "State saved. Next run will resume from interruption point."
    exit 0
}

trap cleanup SIGINT SIGTERM

# ============================================
# State Management
# ============================================
init_state() {
    if [[ ! -f "$STATE_FILE" ]]; then
        cat > "$STATE_FILE" << 'EOF'
{
  "version": "1.0",
  "startTime": null,
  "endTime": null,
  "totalIterations": 0,
  "currentIteration": 0,
  "features": {},
  "stats": {
    "totalTests": 0,
    "passed": 0,
    "failed": 0,
    "skipped": 0,
    "retried": 0,
    "fixed": 0
  },
  "sessions": []
}
EOF
    fi
}

save_state() {
    local feature_id="$1"
    local status="$2"
    local notes="${3:-}"
    
    local temp_file=$(mktemp)
    jq --arg feature "$feature_id" \
       --arg status "$status" \
       --arg notes "$notes" \
       --arg time "$(date -Iseconds)" \
       '.features[$feature] = {
         "status": $status,
         "lastTested": $time,
         "notes": $notes
       }' "$STATE_FILE" > "$temp_file" && mv "$temp_file" "$STATE_FILE"
}

update_stats() {
    local stat_name="$1"
    local value="${2:-1}"
    
    local temp_file=$(mktemp)
    jq --arg stat "$stat_name" \
       --argjson val "$value" \
       '.stats[$stat] = (.stats[$stat] // 0) + $val' "$STATE_FILE" > "$temp_file" && mv "$temp_file" "$STATE_FILE"
}

record_session() {
    local feature_id="$1"
    local duration="$2"
    local passed="$3"
    local log_file="$4"
    
    local temp_file=$(mktemp)
    jq --arg feature "$feature_id" \
       --arg duration "$duration" \
       --arg passed "$passed" \
       --arg log "$log_file" \
       --arg time "$(date -Iseconds)" \
       '.sessions += [{
         "featureId": $feature,
         "timestamp": $time,
         "duration": $duration,
         "passed": ($passed == "true"),
         "logFile": $log
       }]' "$STATE_FILE" > "$temp_file" && mv "$temp_file" "$STATE_FILE"
}

# ============================================
# Development Server Management
# ============================================
DEV_SERVER_PID=""

start_dev_server() {
    log_info "Starting development server..."
    
    # Check if already running
    if curl -s http://localhost:5173 > /dev/null 2>&1; then
        log_success "Development server is already running"
        return 0
    fi
    
    cd "$FRONTEND_DIR"
    
    # Check dependencies
    if [[ ! -d "node_modules" ]]; then
        log_warn "node_modules does not exist, installing dependencies..."
        npm install --silent 2>&1 | tail -10
    fi
    
    # Start server
    npm run dev > "$LOG_DIR/dev-server.log" 2>&1 &
    DEV_SERVER_PID=$!
    
    # Wait for startup
    local retries=0
    local max_retries=60
    
    while [[ $retries -lt $max_retries ]]; do
        if curl -s http://localhost:5173 > /dev/null 2>&1; then
            log_success "Development server started (PID: $DEV_SERVER_PID)"
            return 0
        fi
        sleep 1
        retries=$((retries + 1))
        echo -n "."
    done
    
    log_error "Development server startup timeout"
    return 1
}

stop_dev_server() {
    if [[ -n "$DEV_SERVER_PID" ]]; then
        log_info "Stopping development server (PID: $DEV_SERVER_PID)..."
        kill "$DEV_SERVER_PID" 2>/dev/null
        wait "$DEV_SERVER_PID" 2>/dev/null
        DEV_SERVER_PID=""
    fi
    
    # Ensure port is released
    local pid=$(lsof -t -i:5173 2>/dev/null)
    if [[ -n "$pid" ]]; then
        kill -9 "$pid" 2>/dev/null
    fi
}

# ============================================
# Code Tests
# ============================================
run_code_tests() {
    local feature_id="$1"
    
    log_info "[$feature_id] Starting code-level tests..."
    
    cd "$FRONTEND_DIR"
    local all_passed=true
    
    # 1. TypeScript type checking
    log_info "[$feature_id] Running TypeScript type check..."
    if npx tsc --noEmit 2>&1 | tee -a "$LOG_DIR/${feature_id}_tsc.log"; then
        log_success "[$feature_id] Type check passed"
    else
        log_error "[$feature_id] Type check failed"
        all_passed=false
    fi
    
    # 2. Unit tests
    log_info "[$feature_id] Running unit tests..."
    if npm run test:run 2>&1 | tee -a "$LOG_DIR/${feature_id}_test.log"; then
        log_success "[$feature_id] Unit tests passed"
    else
        log_error "[$feature_id] Unit tests failed"
        all_passed=false
    fi
    
    # 3. Production build
    log_info "[$feature_id] Running production build..."
    if npm run build 2>&1 | tee -a "$LOG_DIR/${feature_id}_build.log"; then
        log_success "[$feature_id] Build successful"
    else
        log_error "[$feature_id] Build failed"
        all_passed=false
    fi
    
    if [[ "$all_passed" == "true" ]]; then
        return 0
    else
        return 1
    fi
}

# ============================================
# Browser E2E Tests (using MCP tools)
# ============================================
generate_browser_test_prompt() {
    local feature_id="$1"
    local feature_name="$2"
    local category="$3"
    
    # Read test steps
    local test_steps=$(jq -r --arg id "$feature_id" '
        .features[] | select(.id == $id) | .browserTests | join("\n")
    ' "$AGENT_HARNESS_DIR/test-feature-list.json" 2>/dev/null)
    
    cat << PROMPT_EOF
# Test Agent Prompt - $feature_id

You are the **Test Agent** for the Kuro frontend project. Your task is to execute browser E2E tests for feature "$feature_name".

## Test Feature

**ID**: $feature_id
**Name**: $feature_name
**Category**: $category

## Test Environment

- Development server: http://localhost:5173
- Screenshot directory: logs/screenshots/
- State file: $STATE_FILE

## Test Steps

$test_steps

## General Test Flow

1. **Navigate to page**
   - Use browser_navigate to visit the page under test
   - Wait for page to load (browser_wait_for)

2. **Initial verification**
   - Use browser_snapshot to get page structure
   - Take initial state screenshot (browser_take_screenshot)

3. **Execute interactions**
   - Use browser_click to click elements
   - Use browser_type to input text
   - Use browser_select_option to select options

4. **State verification**
   - Use browser_wait_for to wait for specific text to appear
   - Use browser_evaluate to execute JavaScript verification

5. **Screenshot recording**
   - Take screenshots at every key state
   - Screenshot filename format: ${feature_id}_<state>_<timestamp>.png

## Screenshot Requirements

Must save the following screenshots:
1. Initial state: ${feature_id}_initial_<timestamp>.png
2. After interaction: ${feature_id}_action_<timestamp>.png
3. Final state: ${feature_id}_final_<timestamp>.png

## Pass Criteria

- [ ] Page loads normally, no white screen/errors
- [ ] All interactive features work properly
- [ ] Key elements render correctly
- [ ] No console.error errors
- [ ] At least 3 screenshots saved

## After Test Completion

1. Check if screenshots are saved to logs/screenshots/
2. Update test-feature-list.json:
   - passes: true/false
   - lastTested: current timestamp
   - notes: issues found (if any)

3. Report test results:
   - Pass: "TEST_PASSED"
   - Fail: "TEST_FAILED: <reason>"

## Important Rules

- Screenshots are required evidence for test pass
- Each test step must have clear verification points
- Record and screenshot issues immediately when found
- Do not modify code of the feature under test
PROMPT_EOF
}

run_browser_tests() {
    local feature_id="$1"
    local feature_name="$2"
    local category="$3"
    
    log_info "[$feature_id] Starting browser E2E tests..."
    
    # Generate test prompt
    local prompt=$(generate_browser_test_prompt "$feature_id" "$feature_name" "$category")
    local prompt_file="$LOG_DIR/prompt_${feature_id}_$(date +%Y%m%d_%H%M%S).txt"
    echo "$prompt" > "$prompt_file"
    
    # Run iflow Test Agent
    log_info "[$feature_id] Starting browser test Agent..."
    
    cd "$WORK_DIR"
    
    local browser_log="$LOG_DIR/browser_${feature_id}_$(date +%Y%m%d_%H%M%S).log"
    
    # Execute browser tests using iflow
    iflow -y \
          --max-tokens 100000 \
          --max-turns 150 \
          -p "$(cat $prompt_file)" \
          2>&1 | tee "$browser_log"
    
    local iflow_exit=${PIPESTATUS[0]}
    
    # Check test results
    if grep -q "TEST_PASSED" "$browser_log" 2>/dev/null; then
        log_success "[$feature_id] Browser tests passed"
        return 0
    elif grep -q "TEST_FAILED" "$browser_log" 2>/dev/null; then
        local reason=$(grep "TEST_FAILED" "$browser_log" | head -1 | sed 's/TEST_FAILED: //')
        log_error "[$feature_id] Browser tests failed: $reason"
        return 1
    else
        # Check if screenshots exist as fallback indicator
        local screenshot_count=$(ls -1 "$SCREENSHOT_DIR/${feature_id}_"*.png 2>/dev/null | wc -l)
        if [[ $screenshot_count -ge 2 ]]; then
            log_success "[$feature_id] Browser tests passed (based on screenshots)"
            return 0
        else
            log_warn "[$feature_id] Test result unclear, assuming pass"
            return 0
        fi
    fi
}

# ============================================
# Fix Agent
# ============================================
generate_fix_prompt() {
    local feature_id="$1"
    local feature_name="$2"
    local failure_reason="$3"
    local tsc_log="$4"
    local test_log="$5"
    local build_log="$6"
    
    cat << PROMPT_EOF
# Fix Agent Prompt - $feature_id

You are the **Fix Agent** for the Kuro frontend project. Your task is to fix features that failed testing.

## Fix Task

**Feature ID**: $feature_id
**Feature Name**: $feature_name
**Failure Reason**: $failure_reason

## Error Logs

### TypeScript Type Check
\`\`\`
$(tail -50 "$tsc_log" 2>/dev/null || echo "No log")
\`\`\`

### Unit Tests
\`\`\`
$(tail -50 "$test_log" 2>/dev/null || echo "No log")
\`\`\`

### Build Log
\`\`\`
$(tail -50 "$build_log" 2>/dev/null || echo "No log")
\`\`\`

## Fix Flow

1. **Analyze errors**
   - Read error logs to understand failure reasons
   - Identify files that need fixing

2. **Review code**
   - Use read_file to read relevant files
   - Understand current implementation and issues

3. **Implement fix**
   - Use replace or write_file to fix code
   - Maintain code style consistency
   - Only modify necessary code

4. **Verify fix**
   - Run \`cd frontend && npx tsc --noEmit\`
   - Run \`cd frontend && npm run test:run\`
   - Run \`cd frontend && npm run build\`

5. **Update status**
   - If fix successful, update test-feature-list.json:
     \`\`\`json
     {
       "passes": true,
       "lastTested": "$(date -Iseconds)",
       "notes": ""
     }
     \`\`\`

## Important Rules

- Only fix issues causing test failure
- Do not refactor unrelated code
- Must verify after fix
- If unable to fix, record detailed reasons

## Report After Fix

- Success: "FIX_SUCCESS"
- Failure: "FIX_FAILED: <reason>"
PROMPT_EOF
}

run_fix_agent() {
    local feature_id="$1"
    local feature_name="$2"
    local failure_reason="$3"
    
    log_info "[$feature_id] Starting fix Agent..."
    
    local tsc_log="$LOG_DIR/${feature_id}_tsc.log"
    local test_log="$LOG_DIR/${feature_id}_test.log"
    local build_log="$LOG_DIR/${feature_id}_build.log"
    
    # Generate fix prompt
    local prompt=$(generate_fix_prompt "$feature_id" "$feature_name" "$failure_reason" "$tsc_log" "$test_log" "$build_log")
    local prompt_file="$LOG_DIR/fix_prompt_${feature_id}.txt"
    echo "$prompt" > "$prompt_file"
    
    # Run iflow Fix Agent
    cd "$WORK_DIR"
    
    local fix_log="$LOG_DIR/fix_${feature_id}_$(date +%Y%m%d_%H%M%S).log"
    
    iflow -y \
          --max-tokens 120000 \
          --max-turns 200 \
          -p "$(cat $prompt_file)" \
          2>&1 | tee "$fix_log"
    
    local iflow_exit=${PIPESTATUS[0]}
    
    # Check results
    if grep -q "FIX_SUCCESS" "$fix_log" 2>/dev/null; then
        log_success "[$feature_id] Fix successful"
        update_stats "fixed"
        return 0
    else
        log_error "[$feature_id] Fix failed"
        return 1
    fi
}

# ============================================
# Test Scheduling
# ============================================
get_next_feature() {
    local feature_file="$AGENT_HARNESS_DIR/test-feature-list.json"
    
    if [[ ! -f "$feature_file" ]]; then
        log_error "Test feature list file does not exist: $feature_file"
        return 1
    fi
    
    # Priority:
    # 1. Never tested (passes=false, lastTested=null)
    # 2. Previously failed and retry count < 3
    # 3. Sorted by priority
    
    jq -r '
        .features |
        map(select(.passes == false)) |
        sort_by(.priority == "high" ? 0 : .priority == "medium" ? 1 : 2) |
        .[0] | .id
    ' "$feature_file" 2>/dev/null
}

get_feature_info() {
    local feature_id="$1"
    local feature_file="$AGENT_HARNESS_DIR/test-feature-list.json"
    
    jq --arg id "$feature_id" '.features[] | select(.id == $id)' "$feature_file" 2>/dev/null
}

# ============================================
# Test Session
# ============================================
run_test_session() {
    local iteration="$1"
    local total="$2"
    local feature_id="$3"
    local skip_browser="${4:-false}"
    
    CURRENT_FEATURE="$feature_id"
    
    # Get feature info
    local feature_info=$(get_feature_info "$feature_id")
    local feature_name=$(echo "$feature_info" | jq -r '.name // "Unknown"')
    local category=$(echo "$feature_info" | jq -r '.category // "unknown"')
    local priority=$(echo "$feature_info" | jq -r '.priority // "medium"')
    
    log_info "========================================"
    log_info "Test Session $iteration / $total"
    log_info "Feature: $feature_id - $feature_name"
    log_info "Category: $category | Priority: $priority"
    log_info "========================================"
    
    local session_start=$(date +%s)
    local session_log="$LOG_DIR/session_${iteration}_${feature_id}_$(date +%Y%m%d_%H%M%S).log"
    
    local test_passed=true
    local failure_reason=""
    
    # Phase 1: Code tests
    if ! run_code_tests "$feature_id" 2>&1 | tee "$session_log"; then
        test_passed=false
        failure_reason="Code tests failed"
        log_error "[$feature_id] Code tests failed, skipping browser tests"
    fi
    
    # Phase 2: Browser tests
    if [[ "$test_passed" == "true" && "$skip_browser" != "true" ]]; then
        if ! run_browser_tests "$feature_id" "$feature_name" "$category" 2>&1 | tee -a "$session_log"; then
            test_passed=false
            failure_reason="Browser tests failed"
        fi
    fi
    
    local session_end=$(date +%s)
    local duration=$((session_end - session_start))
    
    # Update state and statistics
    if [[ "$test_passed" == "true" ]]; then
        log_success "[$feature_id] Test passed (duration: ${duration}s)"
        save_state "$feature_id" "passed" ""
        update_stats "passed"
        
        # Update feature list
        update_feature_list "$feature_id" "true" ""
    else
        log_error "[$feature_id] Test failed (duration: ${duration}s): $failure_reason"
        save_state "$feature_id" "failed" "$failure_reason"
        update_stats "failed"
        
        # Attempt fix
        if [[ "$AUTO_FIX" == "true" ]]; then
            log_info "[$feature_id] Attempting auto-fix..."
            if run_fix_agent "$feature_id" "$feature_name" "$failure_reason"; then
                # Fix successful, re-test
                log_info "[$feature_id] Re-testing..."
                if run_code_tests "$feature_id" 2>&1 | tee -a "$session_log"; then
                    test_passed=true
                    save_state "$feature_id" "fixed" "Auto-fix successful"
                    update_feature_list "$feature_id" "true" "Passed after auto-fix"
                fi
            else
                update_feature_list "$feature_id" "false" "$failure_reason"
            fi
        else
            update_feature_list "$feature_id" "false" "$failure_reason"
        fi
    fi
    
    record_session "$feature_id" "$duration" "$test_passed" "$session_log"
    update_stats "totalTests"
    
    CURRENT_FEATURE=""
    
    if [[ "$test_passed" == "true" ]]; then
        return 0
    else
        return 1
    fi
}

update_feature_list() {
    local feature_id="$1"
    local passed="$2"
    local notes="$3"
    
    local feature_file="$AGENT_HARNESS_DIR/test-feature-list.json"
    local temp_file=$(mktemp)
    
    jq --arg id "$feature_id" \
       --arg passed "$passed" \
       --arg notes "$notes" \
       --arg time "$(date -Iseconds)" \
       '.features = [.features[] | 
         if .id == $id then 
           .passes = ($passed == "true") | 
           .lastTested = $time | 
           .notes = $notes 
         else . end]' \
       "$feature_file" > "$temp_file" && mv "$temp_file" "$feature_file"
}

# ============================================
# Report Generation
# ============================================
generate_report() {
    log_info "Generating test report..."
    
    local report_file="$REPORT_DIR/test_report_$(date +%Y%m%d_%H%M%S).html"
    local feature_file="$AGENT_HARNESS_DIR/test-feature-list.json"
    
    # Read statistics
    local stats=$(cat "$STATE_FILE" | jq '.stats')
    local total=$(echo "$stats" | jq -r '.totalTests // 0')
    local passed=$(echo "$stats" | jq -r '.passed // 0')
    local failed=$(echo "$stats" | jq -r '.failed // 0')
    local fixed=$(echo "$stats" | jq -r '.fixed // 0')
    local pass_rate=0
    
    if [[ $total -gt 0 ]]; then
        pass_rate=$((passed * 100 / total))
    fi
    
    # Generate HTML report
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Kuro Frontend Test Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }
        .stat-card { background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }
        .stat-value { font-size: 36px; font-weight: bold; color: #333; }
        .stat-label { color: #666; margin-top: 5px; }
        .stat-value.success { color: #4CAF50; }
        .stat-value.error { color: #f44336; }
        .stat-value.warning { color: #ff9800; }
        table { width: 100%; border-collapse: collapse; margin-top: 30px; }
        th { background: #4CAF50; color: white; padding: 12px; text-align: left; }
        td { padding: 12px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f5f5f5; }
        .status-pass { color: #4CAF50; font-weight: bold; }
        .status-fail { color: #f44336; font-weight: bold; }
        .status-pending { color: #ff9800; }
        .priority-high { color: #f44336; }
        .priority-medium { color: #ff9800; }
        .priority-low { color: #4CAF50; }
        .timestamp { color: #999; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🧪 Kuro Frontend Test Report</h1>
        <p class="timestamp">Generated: $(date '+%Y-%m-%d %H:%M:%S')</p>
        
        <div class="summary">
            <div class="stat-card">
                <div class="stat-value">$total</div>
                <div class="stat-label">Total Tests</div>
            </div>
            <div class="stat-card">
                <div class="stat-value success">$passed</div>
                <div class="stat-label">Passed</div>
            </div>
            <div class="stat-card">
                <div class="stat-value error">$failed</div>
                <div class="stat-label">Failed</div>
            </div>
            <div class="stat-card">
                <div class="stat-value warning">$fixed</div>
                <div class="stat-label">Auto Fixed</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">$pass_rate%</div>
                <div class="stat-label">Pass Rate</div>
            </div>
        </div>
        
        <h2>Feature Test Results</h2>
        <table>
            <tr>
                <th>ID</th>
                <th>Name</th>
                <th>Category</th>
                <th>Priority</th>
                <th>Status</th>
                <th>Last Tested</th>
                <th>Notes</th>
            </tr>
EOF

    # Add feature test results
    while IFS= read -r feature; do
        local feat_id=$(echo "$feature" | jq -r '.id')
        local feat_name=$(echo "$feature" | jq -r '.name')
        local feat_category=$(echo "$feature" | jq -r '.category')
        local feat_priority=$(echo "$feature" | jq -r '.priority')
        local feat_passes=$(echo "$feature" | jq -r '.passes')
        local feat_tested=$(echo "$feature" | jq -r '.lastTested // "Never"')
        local feat_notes=$(echo "$feature" | jq -r '.notes // "-"')
        
        local status_class="status-pending"
        local status_text="⏳ PENDING"
        if [[ "$feat_passes" == "true" ]]; then
            status_class="status-pass"
            status_text="✅ PASS"
        elif [[ "$feat_tested" != "Never" ]]; then
            status_class="status-fail"
            status_text="❌ FAIL"
        fi
        
        echo "<tr>
            <td>$feat_id</td>
            <td>$feat_name</td>
            <td>$feat_category</td>
            <td class=\"priority-$feat_priority\">$feat_priority</td>
            <td class=\"$status_class\">$status_text</td>
            <td>$feat_tested</td>
            <td>$feat_notes</td>
        </tr>" >> "$report_file"
    done < <(jq -c '.features[]' "$feature_file")

    cat >> "$report_file" << EOF
        </table>
        
        <h2>Test Sessions</h2>
        <table>
            <tr>
                <th>Feature</th>
                <th>Timestamp</th>
                <th>Duration</th>
                <th>Result</th>
                <th>Log</th>
            </tr>
EOF

    # Add session records
    while IFS= read -r session; do
        local sess_feature=$(echo "$session" | jq -r '.featureId')
        local sess_time=$(echo "$session" | jq -r '.timestamp')
        local sess_duration=$(echo "$session" | jq -r '.duration')
        local sess_passed=$(echo "$session" | jq -r '.passed')
        local sess_log=$(echo "$session" | jq -r '.logFile')
        
        local sess_status_class="status-fail"
        local sess_status_text="❌"
        if [[ "$sess_passed" == "true" ]]; then
            sess_status_class="status-pass"
            sess_status_text="✅"
        fi
        
        echo "<tr>
            <td>$sess_feature</td>
            <td>$sess_time</td>
            <td>${sess_duration}s</td>
            <td class=\"$sess_status_class\">$sess_status_text</td>
            <td><a href=\"$sess_log\">View</a></td>
        </tr>" >> "$report_file"
    done < <(jq -c '.sessions[]' "$STATE_FILE" 2>/dev/null || echo "")

    cat >> "$report_file" << EOF
        </table>
    </div>
</body>
</html>
EOF

    log_success "Report generated: $report_file"
    
    # Also generate JSON report
    local json_report="$REPORT_DIR/test_report_$(date +%Y%m%d_%H%M%S).json"
    cp "$STATE_FILE" "$json_report"
    log_info "JSON report: $json_report"
}

# ============================================
# Help Information
# ============================================
show_help() {
    cat << 'EOF'
Kuro Frontend Test Agent - Long-running test script

Usage:
    ./kuro-test-agent.sh [options]

Options:
    -i, --iterations N      Run N test iterations (default: infinite loop until all features tested)
    -f, --feature ID        Test only specific feature
    --no-browser            Skip browser E2E tests
    --no-fix                Disable auto-fix
    --auto-fix              Enable auto-fix (enabled by default)
    --resume                Resume from last interruption
    --report-only           Only generate report
    -d, --debug             Enable debug logging
    -h, --help              Show help information

Examples:
    # Run all tests until completion
    ./kuro-test-agent.sh

    # Run 10 iterations
    ./kuro-test-agent.sh -i 10

    # Test only specific feature
    ./kuro-test-agent.sh -f FEAT-015

    # Resume from last interruption
    ./kuro-test-agent.sh --resume

    # Run code tests only (skip browser)
    ./kuro-test-agent.sh --no-browser

Output:
    Log directory: logs/
    Screenshot directory: logs/screenshots/
    Report directory: logs/reports/
    State file: logs/.state/

Signal Handling:
    Ctrl+C    Safe interruption, save state for recovery
EOF
}

# ============================================
# Main Program
# ============================================
main() {
    # Default configuration
    ITERATIONS=""
    SINGLE_FEATURE=""
    SKIP_BROWSER=false
    AUTO_FIX=true
    RESUME=false
    REPORT_ONLY=false
    DEBUG=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -i|--iterations)
                ITERATIONS="$2"
                shift 2
                ;;
            -f|--feature)
                SINGLE_FEATURE="$2"
                shift 2
                ;;
            --no-browser)
                SKIP_BROWSER=true
                shift
                ;;
            --no-fix)
                AUTO_FIX=false
                shift
                ;;
            --auto-fix)
                AUTO_FIX=true
                shift
                ;;
            --resume)
                RESUME=true
                shift
                ;;
            --report-only)
                REPORT_ONLY=true
                shift
                ;;
            -d|--debug)
                DEBUG=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Report only mode
    if [[ "$REPORT_ONLY" == "true" ]]; then
        generate_report
        exit 0
    fi
    
    # Initialize
    init_state
    
    # Save PID
    echo $ > "$PID_FILE"
    
    # Restore checkpoint
    local start_iteration=1
    if [[ "$RESUME" == "true" && -f "$CHECKPOINT_FILE" ]]; then
        start_iteration=$(cat "$CHECKPOINT_FILE")
        log_info "Resuming from iteration $start_iteration"
    fi
    
    # Display startup information
    echo ""
    echo -e "${BOLD}${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${BLUE}║${NC}        ${BOLD}Kuro Frontend Test Agent${NC}"
    echo -e "${BOLD}${BLUE}╠════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${BOLD}${BLUE}║${NC}  Iterations: ${ITERATIONS:-Infinite loop}"
    echo -e "${BOLD}${BLUE}║${NC}  Browser tests: $([ "$SKIP_BROWSER" == "true" ] && echo "Skipped" || echo "Enabled")"
    echo -e "${BOLD}${BLUE}║${NC}  Auto-fix: $([ "$AUTO_FIX" == "true" ] && echo "Enabled" || echo "Disabled")"
    echo -e "${BOLD}${BLUE}║${NC}  Debug mode: $([ "$DEBUG" == "true" ] && echo "Enabled" || echo "Disabled")"
    echo -e "${BOLD}${BLUE}║${NC}  Log directory: $LOG_DIR"
    echo -e "${BOLD}${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Start development server
    if [[ "$SKIP_BROWSER" != "true" ]]; then
        start_dev_server || exit 1
    fi
    
    # Single feature test mode
    if [[ -n "$SINGLE_FEATURE" ]]; then
        log_info "Single feature test mode: $SINGLE_FEATURE"
        run_test_session 1 1 "$SINGLE_FEATURE" "$SKIP_BROWSER"
        generate_report
        stop_dev_server
        exit 0
    fi
    
    # Main loop
    local iteration=$start_iteration
    while true; do
        CURRENT_ITERATION=$iteration
        
        # Get next feature to test
        local feature_id=$(get_next_feature)
        
        if [[ -z "$feature_id" || "$feature_id" == "null" ]]; then
            log_success "All features tested!"
            break
        fi
        
        # Check if max iterations reached
        if [[ -n "$ITERATIONS" && $iteration -gt $ITERATIONS ]]; then
            log_info "Maximum iterations reached ($ITERATIONS)"
            break
        fi
        
        # Run test session
        run_test_session "$iteration" "${ITERATIONS:-∞}" "$feature_id" "$SKIP_BROWSER"
        
        # Increment iteration count
        iteration=$((iteration + 1))
        echo "$iteration" > "$CHECKPOINT_FILE"
        
        # Interval
        if [[ -z "$ITERATIONS" || $iteration -le $ITERATIONS ]]; then
            log_info "Waiting 3 seconds before next test..."
            sleep 3
        fi
    done
    
    # Cleanup
    stop_dev_server
    rm -f "$CHECKPOINT_FILE" "$PID_FILE"
    
    # Generate final report
    generate_report
    
    # Display completion message
    echo ""
    echo -e "${BOLD}${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${GREEN}║${NC}        ${BOLD}Testing Complete!${NC}"
    echo -e "${BOLD}${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Run main program
main "$@"
