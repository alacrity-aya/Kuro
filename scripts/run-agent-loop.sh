#!/bin/bash
# loop_iflow.sh - Loop running iflow to execute multiple development cycles
# Usage: ./loop_iflow.sh <count>

# ============================================
# Configuration
# ============================================
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
WORK_DIR="$PROJECT_ROOT"
FRONTEND_DIR="$WORK_DIR/frontend"

# Log files
LOG_DIR="$PROJECT_ROOT/logs"
mkdir -p "$LOG_DIR"
MAIN_LOG="$LOG_DIR/loop_$(date +%Y%m%d_%H%M%S).log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Loop counter file (for resuming after Ctrl+C)
COUNTER_FILE="$LOG_DIR/.loop_counter"

# ============================================
# Signal handling - Graceful exit
# ============================================
cleanup() {
    echo ""
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW}  Received interrupt signal, saving state...${NC}"
    echo -e "${YELLOW}========================================${NC}"
    
    # Save current progress
    echo "$CURRENT_ITERATION" > "$COUNTER_FILE"
    
    echo -e "${GREEN}State saved. Next run will continue from iteration $((CURRENT_ITERATION + 1)).${NC}"
    echo -e "${CYAN}Log directory: $LOG_DIR${NC}"
    exit 0
}

trap cleanup SIGINT SIGTERM

# ============================================
# Help information
# ============================================
show_help() {
    echo "Long Running Agent Loop Script"
    echo ""
    echo "Usage: $0 <loop_count>"
    echo ""
    echo "Arguments:"
    echo "  loop_count    Number of times to execute iflow"
    echo ""
    echo "Examples:"
    echo "  $0 10    # Run 10 times"
    echo "  $0 5     # Run 5 times"
    echo ""
    echo "Options:"
    echo "  -h, --help    Show help information"
    echo "  --resume      Resume from last interruption"
    echo "  --no-verify   Skip test verification"
    echo ""
    echo "Log directory: $LOG_DIR"
}

# ============================================
# Get feature progress
# ============================================
get_feature_progress() {
    local feature_file="$WORK_DIR/agent-harness/feature_list.json"
    if [ -f "$feature_file" ]; then
        if command -v jq &> /dev/null; then
            local total=$(jq 'length' "$feature_file" 2>/dev/null || echo "0")
            local complete=$(jq '[.[] | select(.passes == true)] | length' "$feature_file" 2>/dev/null || echo "0")
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
# Show session start information
# ============================================
show_session_header() {
    local session=$1
    local total=$2
    
    echo ""
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║${NC}  ${BOLD}Session $session / $total${NC}"
    echo -e "${BOLD}${CYAN}╠══════════════════════════════════════════════════╣${NC}"
    echo -e "${BOLD}${CYAN}║${NC}  Progress: $(get_feature_progress)"
    echo -e "${BOLD}${CYAN}║${NC}  Directory: $WORK_DIR"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ============================================
# Show session end information
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
    if [ ! -d "$FRONTEND_DIR" ]; then
        echo -e "${YELLOW}  ⚠ frontend directory does not exist, skipping build verification${NC}"
        return 0
    fi
    
    echo -e "${CYAN}  🔍 Running build verification...${NC}"
    
    cd "$FRONTEND_DIR"
    
    # Check node_modules
    if [ ! -d "node_modules" ]; then
        echo -e "${YELLOW}  📦 Installing dependencies...${NC}"
        npm install --silent 2>&1 | tail -5
    fi
    
    # Run build
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
# Reset last completed feature in feature_list.json
# ============================================
reset_last_feature() {
    local feature_file="$WORK_DIR/agent-harness/feature_list.json"
    if [ -f "$feature_file" ] && command -v jq &> /dev/null; then
        # Find last feature with passes: true and reset it
        jq '(. | map(select(.passes == true)) | last | .passes = false) // empty | . as $last | .[] | if .id == $last.id then .passes = false else . end' "$feature_file" > "${feature_file}.tmp" 2>/dev/null
        if [ -s "${feature_file}.tmp" ]; then
            mv "${feature_file}.tmp" "$feature_file"
            echo -e "${YELLOW}  Reset last completed feature in feature_list.json${NC}"
        else
            rm -f "${feature_file}.tmp"
        fi
    fi
}

# ============================================
# Generate iflow prompt
# ============================================
generate_prompt() {
    cat << 'PROMPT_EOF'
You are the Coding Agent, responsible for developing the Kuro frontend project.

## ⚠️ Key Requirements: Must pass tests before completion

**Before marking any feature as complete, you must perform the following verification steps:**

1. Run build: `cd frontend && npm run build`
2. Ensure build succeeds without any errors
3. Only proceed if build is successful

**If build fails:**
- Fix errors and rebuild
- Do not mark feature as complete
- Do not commit code

## Startup Routine Check (Must Execute)

1. Confirm working directory:
   ```bash
   pwd
   ```

2. Read progress file:
   ```bash
   cat agent-harness/claude-progress.txt
   ```

3. Read feature list:
   ```bash
   cat agent-harness/feature_list.json
   ```

4. View recent git commits:
   ```bash
   git log --oneline -10
   ```

## Workflow

1. **Select Feature**: Choose the highest priority incomplete feature from agent-harness/feature_list.json (passes: false)

2. **Implement Feature**: Write code, keep it simple and focused

3. **⚠️ Test Verification (Must Pass), Need to test current feature functionality and code build**:
   ```bash
   cd frontend
   npm install  # If needed
   npm run build  # Must succeed!
   ```

4. **Commit Code** (Only after tests pass):
   ```bash
   git add .
   git commit -m "feat: [feature description]"
   ```

5. **Update Feature List**: Only modify the passes field of the corresponding feature to true

6. **Update Progress File**: Append session record to agent-harness/claude-progress.txt

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
3. Next step suggestions
PROMPT_EOF
}

# ============================================
# Run single iflow session
# ============================================
run_iflow_session() {
    local session_num=$1
    local total=$2
    local no_verify=$3
    
    # Show session header
    show_session_header "$session_num" "$total" | tee -a "$MAIN_LOG" > /dev/tty
    
    # Session log file
    local session_log="$LOG_DIR/session_${session_num}_$(date +%Y%m%d_%H%M%S).log"
    
    # Generate prompt
    local prompt=$(generate_prompt)
    
    cd "$WORK_DIR"
    
    local start_time=$(date +%s)
    
    # Record commit count before session
    local commits_before=$(git rev-list --count HEAD 2>/dev/null || echo "0")
    
    # Run iflow - pass through output directly
    iflow -y \
          --max-tokens 100000 \
          --max-turns 50 \
          -p "$prompt" \
          2>&1 | tee "$session_log"
    
    local exit_code=${PIPESTATUS[0]}
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Verification phase
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
    
    # Show session footer
    show_session_footer "$duration" "$verified" | tee -a "$MAIN_LOG" > /dev/tty
    
    return 0
}

# ============================================
# Check if all features are complete
# ============================================
check_completion() {
    local feature_file="$WORK_DIR/agent-harness/feature_list.json"
    if [ -f "$feature_file" ] && command -v jq &> /dev/null; then
        local incomplete=$(jq '[.[] | select(.passes == false)] | length' "$feature_file" 2>/dev/null || echo "1")
        if [ "$incomplete" -eq 0 ]; then
            return 0  # All features complete
        fi
    fi
    return 1  # Still have incomplete features
}

# ============================================
# Main program
# ============================================

# Parse arguments
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

# If no loop count specified
if [ -z "$ITERATIONS" ]; then
    echo "Error: Please specify loop count"
    show_help
    exit 1
fi

# Restore or initialize counter
if [ "$RESUME" = true ] && [ -f "$COUNTER_FILE" ]; then
    START_ITERATION=$(($(cat "$COUNTER_FILE") + 1))
    echo -e "${GREEN}Resuming from last interruption, starting from iteration $START_ITERATION${NC}"
else
    START_ITERATION=1
fi

# Start
echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║${NC}     ${BOLD}Kuro Frontend Development - Long Running Agent${NC}"
echo -e "${BOLD}${BLUE}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}${BLUE}║${NC}  Loop count: $ITERATIONS"
echo -e "${BOLD}${BLUE}║${NC}  Working directory: $WORK_DIR"
echo -e "${BOLD}${BLUE}║${NC}  Log directory: $LOG_DIR"
echo -e "${BOLD}${BLUE}║${NC}  Verification mode: $([ "$NO_VERIFY" = true ] && echo "disabled" || echo "enabled")"
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# Main loop
CURRENT_ITERATION=$START_ITERATION
for i in $(seq "$START_ITERATION" "$ITERATIONS"); do
    CURRENT_ITERATION=$i
    
    run_iflow_session "$i" "$ITERATIONS" "$NO_VERIFY"
    
    # Check if all features are complete
    if check_completion; then
        echo ""
        echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}  🎉 All features completed! Ending loop early.${NC}"
        echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
        rm -f "$COUNTER_FILE"
        exit 0
    fi
    
    # If not the last iteration, show separator
    if [ "$i" -lt "$ITERATIONS" ]; then
        echo ""
        echo -e "${YELLOW}>>> Waiting 3 seconds before next session... (Ctrl+C to safely interrupt)${NC}"
        sleep 3
    fi
done

# End
echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║${NC}     ${BOLD}Loop execution completed!${NC}"
echo -e "${BOLD}${GREEN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}${GREEN}║${NC}  Total executions: $ITERATIONS"
echo -e "${BOLD}${GREEN}║${NC}  Final progress: $(get_feature_progress)"
echo -e "${BOLD}${GREEN}║${NC}  Log directory: $LOG_DIR"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# Clean up counter file
rm -f "$COUNTER_FILE"
