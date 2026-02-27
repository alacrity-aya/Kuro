#!/bin/bash
# Kuro Test Agent Monitor - Test Monitoring Script
# Used to monitor long-running test agent status

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_DIR="$PROJECT_ROOT/logs"
STATE_DIR="$LOG_DIR/.state"
PID_FILE="$STATE_DIR/agent.pid"
STATE_FILE="$STATE_DIR/test_state.json"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

show_status() {
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}           ${CYAN}Kuro Test Agent Status Monitor${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Check if agent is running
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if ps -p "$pid" > /dev/null 2>&1; then
            echo -e "Agent Status: ${GREEN}Running${NC} (PID: $pid)"
        else
            echo -e "Agent Status: ${RED}Not Running${NC} (PID file exists but process not found)"
        fi
    else
        echo -e "Agent Status: ${YELLOW}Not Started${NC}"
    fi
    echo ""
    
    # Show statistics
    if [[ -f "$STATE_FILE" ]]; then
        echo -e "${CYAN}Test Statistics:${NC}"
        echo "------------------------------"
        
        local total=$(jq -r '.stats.totalTests // 0' "$STATE_FILE")
        local passed=$(jq -r '.stats.passed // 0' "$STATE_FILE")
        local failed=$(jq -r '.stats.failed // 0' "$STATE_FILE")
        local fixed=$(jq -r '.stats.fixed // 0' "$STATE_FILE")
        
        echo -e "  Total Tests:  ${BLUE}$total${NC}"
        echo -e "  Passed:       ${GREEN}$passed${NC}"
        echo -e "  Failed:       ${RED}$failed${NC}"
        echo -e "  Auto Fixed:   ${YELLOW}$fixed${NC}"
        
        if [[ $total -gt 0 ]]; then
            local rate=$((passed * 100 / total))
            echo -e "  Pass Rate:    ${GREEN}$rate%${NC}"
        fi
        echo ""
        
        # Show recent sessions
        echo -e "${CYAN}Recent Tests:${NC}"
        echo "------------------------------"
        jq -r '.sessions[-5:] | reverse | .[] | 
            "  \(.timestamp): \(.featureId) - \(if .passed then "✅ PASS" else "❌ FAIL" end) (\(.duration)s)"' "$STATE_FILE" 2>/dev/null || echo "  No data available"
        echo ""
    fi
    
    # Show feature test status
    local feature_file="$PROJECT_ROOT/agent-harness/test-feature-list.json"
    if [[ -f "$feature_file" ]]; then
        echo -e "${CYAN}Feature Test Status:${NC}"
        echo "------------------------------"
        
        local passed_count=$(jq '[.features[] | select(.passes == true)] | length' "$feature_file")
        local failed_count=$(jq '[.features[] | select(.passes == false and .lastTested != null)] | length' "$feature_file")
        local pending_count=$(jq '[.features[] | select(.passes == false and .lastTested == null)] | length' "$feature_file")
        local total_count=$(jq '.features | length' "$feature_file")
        
        echo -e "  Passed:  ${GREEN}$passed_count${NC} / $total_count"
        echo -e "  Failed:  ${RED}$failed_count${NC} / $total_count"
        echo -e "  Pending: ${YELLOW}$pending_count${NC} / $total_count"
        echo ""
        
        # Show pending features
        if [[ $pending_count -gt 0 ]]; then
            echo -e "${YELLOW}Pending Features:${NC}"
            jq -r '.features[] | select(.passes == false and .lastTested == null) | 
                "  - \(.id): \(.name) [\(.priority)]"' "$feature_file"
            echo ""
        fi
        
        # Show failed features
        if [[ $failed_count -gt 0 ]]; then
            echo -e "${RED}Failed Features:${NC}"
            jq -r '.features[] | select(.passes == false and .lastTested != null) | 
                "  - \(.id): \(.name) - \(.notes // "No notes")"' "$feature_file"
            echo ""
        fi
    fi
    
    # Show log information
    echo -e "${CYAN}Log Information:${NC}"
    echo "------------------------------"
    echo "  Main Log:       $LOG_DIR/agent.log"
    echo "  Screenshots:    $LOG_DIR/screenshots/"
    echo "  Reports:        $LOG_DIR/reports/"
    
    local log_size=$(du -sh "$LOG_DIR" 2>/dev/null | cut -f1)
    echo "  Log Size:       $log_size"
    echo ""
}

show_logs() {
    local lines="${1:-50}"
    if [[ -f "$LOG_DIR/agent.log" ]]; then
        echo -e "${CYAN}Last $lines lines of log:${NC}"
        echo "------------------------------"
        tail -n "$lines" "$LOG_DIR/agent.log"
    else
        echo -e "${YELLOW}No log file available${NC}"
    fi
}

watch_mode() {
    while true; do
        clear
        show_status
        echo "Press Ctrl+C to exit monitoring"
        sleep 5
    done
}

generate_quick_report() {
    local report_file="$LOG_DIR/quick_report.txt"
    
    echo "Kuro Frontend Test Report" > "$report_file"
    echo "Generated: $(date '+%Y-%m-%d %H:%M:%S')" >> "$report_file"
    echo "=======================================" >> "$report_file"
    echo "" >> "$report_file"
    
    if [[ -f "$STATE_FILE" ]]; then
        echo "Statistics:" >> "$report_file"
        jq -r '.stats | to_entries[] | "  \(.key): \(.value)"' "$STATE_FILE" >> "$report_file"
        echo "" >> "$report_file"
        
        echo "Recent Sessions:" >> "$report_file"
        jq -r '.sessions[-10:] | .[] | 
            "  - \(.timestamp): \(.featureId) (\(if .passed then "PASS" else "FAIL" end))"' "$STATE_FILE" >> "$report_file"
    fi
    
    echo "" >> "$report_file"
    echo "Feature Status:" >> "$report_file"
    
    local feature_file="$PROJECT_ROOT/agent-harness/test-feature-list.json"
    if [[ -f "$feature_file" ]]; then
        jq -r '.features[] | 
            "  - \(.id): \(if .passes then "✅" else "❌" end) \(.name)"' "$feature_file" >> "$report_file"
    fi
    
    echo ""
    echo -e "${GREEN}Quick report generated: $report_file${NC}"
    cat "$report_file"
}

# Main program
case "${1:-status}" in
    status)
        show_status
        ;;
    logs)
        show_logs "${2:-50}"
        ;;
    watch)
        watch_mode
        ;;
    report)
        generate_quick_report
        ;;
    help)
        echo "Kuro Test Agent Monitor"
        echo ""
        echo "Usage:"
        echo "  $0 status    Show current status"
        echo "  $0 logs [N]  Show last N lines of log (default: 50)"
        echo "  $0 watch     Continuous monitoring mode"
        echo "  $0 report    Generate quick report"
        echo "  $0 help      Show this help"
        ;;
    *)
        echo "Unknown command: $1"
        echo "Use '$0 help' to see available commands"
        exit 1
        ;;
esac