#!/bin/bash
# Kuro Test Agent Quick Start - 快速启动脚本
# 提供常用测试场景的快捷命令

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_SCRIPT="$SCRIPT_DIR/kuro-test-agent.sh"

# 颜色
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
    echo -e "${BOLD}${BLUE}║${NC}     ${BOLD}Kuro Frontend Test Agent - 快速启动${NC}"
    echo -e "${BOLD}${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "常用命令:"
    echo ""
    echo -e "  ${CYAN}1${NC}. 完整测试 (所有功能)"
    echo "     $0 full"
    echo ""
    echo -e "  ${CYAN}2${NC}. 代码测试 (跳过浏览器)"
    echo "     $0 code"
    echo ""
    echo -e "  ${CYAN}3${NC}. 单个功能测试"
    echo "     $0 single FEAT-015"
    echo ""
    echo -e "  ${CYAN}4${NC}. 继续上次测试"
    echo "     $0 resume"
    echo ""
    echo -e "  ${CYAN}5${NC}. 生成报告"
    echo "     $0 report"
    echo ""
    echo -e "  ${CYAN}6${NC}. 监控状态"
    echo "     $0 monitor"
    echo ""
    echo -e "  ${CYAN}7${NC}. 清理日志"
    echo "     $0 clean"
    echo ""
    echo -e "  ${CYAN}0${NC}. 退出"
    echo ""
}

run_full_test() {
    echo -e "${CYAN}启动完整测试...${NC}"
    "$AGENT_SCRIPT" --auto-fix
}

run_code_test() {
    echo -e "${CYAN}启动代码测试 (跳过浏览器)...${NC}"
    "$AGENT_SCRIPT" --no-browser --auto-fix
}

run_single_test() {
    local feature="${1:-}"
    if [[ -z "$feature" ]]; then
        echo -n "请输入功能ID (如 FEAT-015): "
        read feature
    fi
    
    echo -e "${CYAN}测试功能: $feature${NC}"
    "$AGENT_SCRIPT" --feature "$feature" --auto-fix
}

run_resume() {
    echo -e "${CYAN}从上次中断处恢复...${NC}"
    "$AGENT_SCRIPT" --resume --auto-fix
}

generate_report() {
    echo -e "${CYAN}生成测试报告...${NC}"
    "$AGENT_SCRIPT" --report-only
}

show_monitor() {
    "$SCRIPT_DIR/kuro-test-monitor.sh" status
}

clean_logs() {
    echo -e "${YELLOW}清理日志文件...${NC}"
    local LOG_DIR="$(dirname "$SCRIPT_DIR")/logs"
    
    if [[ -d "$LOG_DIR" ]]; then
        rm -rf "$LOG_DIR"/*.log
        rm -rf "$LOG_DIR"/screenshots/*.png
        rm -rf "$LOG_DIR"/.state/*
        echo -e "${GREEN}日志已清理${NC}"
    else
        echo -e "${YELLOW}日志目录不存在${NC}"
    fi
}

# 交互模式
interactive_mode() {
    while true; do
        show_menu
        echo -n "请选择 [0-7]: "
        read choice
        
        case $choice in
            1) run_full_test; break ;;
            2) run_code_test; break ;;
            3) run_single_test; break ;;
            4) run_resume; break ;;
            5) generate_report; break ;;
            6) show_monitor; break ;;
            7) clean_logs; break ;;
            0) echo "退出"; exit 0 ;;
            *) echo -e "${RED}无效选择${NC}"; sleep 1 ;;
        esac
    done
}

# 命令模式
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
        echo "未知命令: $1"
        show_menu
        exit 1
        ;;
esac