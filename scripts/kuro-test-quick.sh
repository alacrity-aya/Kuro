#!/bin/bash
# Kuro Test Agent Quick Start - Quick Launch Script
# Provides shortcut commands for common test scenarios

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_SCRIPT="$SCRIPT_DIR/kuro-test-agent.sh"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

show_menu() {
    echo ""
    echo -e "${BOLD}${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${BLUE}║${NC}     ${BOLD}Kuro Frontend Test Agent - Quick Launch${NC}"
    echo -e "${BOLD}${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Common commands:"
    echo ""
    echo -e "  ${CYAN}1${NC}. Full test (all features)"
    echo "     $0 full"
    echo ""
    echo -e "  ${CYAN}2${NC}. Code test (skip browser)"
    echo "     $0 code"
    echo ""
    echo -e "  ${CYAN}3${NC}. Single feature test"
    echo "     $0 single FEAT-015"
    echo ""
    echo -e "  ${CYAN}4${NC}. Resume last test"
    echo "     $0 resume"
    echo ""
    echo -e "  ${CYAN}5${NC}. Generate report"
    echo "     $0 report"
    echo ""
    echo -e "  ${CYAN}6${NC}. Monitor status"
    echo "     $0 monitor"
    echo ""
    echo -e "  ${CYAN}7${NC}. Clean logs"
    echo "     $0 clean"
    echo ""
    echo -e "  ${CYAN}0${NC}. Exit"
    echo ""
}

run_full_test() {
    echo -e "${CYAN}Starting full test...${NC}"
    "$AGENT_SCRIPT" --auto-fix
}

run_code_test() {
    echo -e "${CYAN}Starting code test (skip browser)...${NC}"
    "$AGENT_SCRIPT" --no-browser --auto-fix
}

run_single_test() {
    local feature="${1:-}"
    if [[ -z "$feature" ]]; then
        echo -n "Enter feature ID (e.g., FEAT-015): "
        read feature
    fi

    echo -e "${CYAN}Testing feature: $feature${NC}"
    "$AGENT_SCRIPT" --feature "$feature" --auto-fix
}

run_resume() {
    echo -e "${CYAN}Resuming from last interruption...${NC}"
    "$AGENT_SCRIPT" --resume --auto-fix
}

generate_report() {
    echo -e "${CYAN}Generating test report...${NC}"
    "$AGENT_SCRIPT" --report-only
}

show_monitor() {
    "$SCRIPT_DIR/kuro-test-monitor.sh" status
}

clean_logs() {
    echo -e "${YELLOW}Cleaning log files...${NC}"
    local LOG_DIR="$(dirname "$SCRIPT_DIR")/logs"

    if [[ -d "$LOG_DIR" ]]; then
        rm -rf "$LOG_DIR"/*.log
        rm -rf "$LOG_DIR"/screenshots/*.png
        rm -rf "$LOG_DIR"/.state/*
        echo -e "${GREEN}Logs cleaned${NC}"
    else
        echo -e "${YELLOW}Log directory does not exist${NC}"
    fi
}

# Interactive mode
interactive_mode() {
    while true; do
        show_menu
        echo -n "Select [0-7]: "
        read choice

        case $choice in
            1) run_full_test; break ;;
            2) run_code_test; break ;;
            3) run_single_test; break ;;
            4) run_resume; break ;;
            5) generate_report; break ;;
            6) show_monitor; break ;;
            7) clean_logs; break ;;
            0) echo "Exit"; exit 0 ;;
            *) echo -e "${RED}Invalid selection${NC}"; sleep 1 ;;
        esac
    done
}

# Command mode
case "${1:-menu}" in
    menu)
        interactive_mode
        ;;
    full)
        run_full_test
        ;;
    code)
        run_code_test
        ;;
    single)
        run_single_test "$2"
        ;;
    resume)
        run_resume
        ;;
    report)
        generate_report
        ;;
    monitor)
        show_monitor
        ;;
    clean)
        clean_logs
        ;;
    help)
        show_menu
        ;;
    *)
        echo "Unknown command: $1"
        show_menu
        exit 1
        ;;
esac