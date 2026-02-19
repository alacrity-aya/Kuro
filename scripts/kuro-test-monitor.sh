#!/bin/bash
# Kuro Test Agent Monitor - 测试监控脚本
# 用于监控长时间运行的测试agent状态

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_DIR="$PROJECT_ROOT/logs"
STATE_DIR="$LOG_DIR/.state"
PID_FILE="$STATE_DIR/agent.pid"
STATE_FILE="$STATE_DIR/test_state.json"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

show_status() {
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}           ${CYAN}Kuro Test Agent 状态监控${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # 检查agent是否在运行
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if ps -p "$pid" > /dev/null 2>&1; then
            echo -e "Agent状态: ${GREEN}运行中${NC} (PID: $pid)"
        else
            echo -e "Agent状态: ${RED}未运行${NC} (PID文件存在但进程不存在)"
        fi
    else
        echo -e "Agent状态: ${YELLOW}未启动${NC}"
    fi
    echo ""
    
    # 显示统计数据
    if [[ -f "$STATE_FILE" ]]; then
        echo -e "${CYAN}测试统计:${NC}"
        echo "------------------------------"
        
        local total=$(jq -r '.stats.totalTests // 0' "$STATE_FILE")
        local passed=$(jq -r '.stats.passed // 0' "$STATE_FILE")
        local failed=$(jq -r '.stats.failed // 0' "$STATE_FILE")
        local fixed=$(jq -r '.stats.fixed // 0' "$STATE_FILE")
        
        echo -e "  总测试数:   ${BLUE}$total${NC}"
        echo -e "  通过:       ${GREEN}$passed${NC}"
        echo -e "  失败:       ${RED}$failed${NC}"
        echo -e "  自动修复:   ${YELLOW}$fixed${NC}"
        
        if [[ $total -gt 0 ]]; then
            local rate=$((passed * 100 / total))
            echo -e "  通过率:     ${GREEN}$rate%${NC}"
        fi
        echo ""
        
        # 显示最近的会话
        echo -e "${CYAN}最近测试:${NC}"
        echo "------------------------------"
        jq -r '.sessions[-5:] | reverse | .[] | 
            "  \(.timestamp): \(.featureId) - \(if .passed then "✅ PASS" else "❌ FAIL" end) (\(.duration)s)"' "$STATE_FILE" 2>/dev/null || echo "  暂无数据"
        echo ""
    fi
    
    # 显示功能测试状态
    local feature_file="$PROJECT_ROOT/agent-harness/test-feature-list.json"
    if [[ -f "$feature_file" ]]; then
        echo -e "${CYAN}功能测试状态:${NC}"
        echo "------------------------------"
        
        local passed_count=$(jq '[.features[] | select(.passes == true)] | length' "$feature_file")
        local failed_count=$(jq '[.features[] | select(.passes == false and .lastTested != null)] | length' "$feature_file")
        local pending_count=$(jq '[.features[] | select(.passes == false and .lastTested == null)] | length' "$feature_file")
        local total_count=$(jq '.features | length' "$feature_file")
        
        echo -e "  通过:   ${GREEN}$passed_count${NC} / $total_count"
        echo -e "  失败:   ${RED}$failed_count${NC} / $total_count"
        echo -e "  待测:   ${YELLOW}$pending_count${NC} / $total_count"
        echo ""
        
        # 显示待测功能
        if [[ $pending_count -gt 0 ]]; then
            echo -e "${YELLOW}待测功能:${NC}"
            jq -r '.features[] | select(.passes == false and .lastTested == null) | 
                "  - \(.id): \(.name) [\(.priority)]"' "$feature_file"
            echo ""
        fi
        
        # 显示失败功能
        if [[ $failed_count -gt 0 ]]; then
            echo -e "${RED}失败功能:${NC}"
            jq -r '.features[] | select(.passes == false and .lastTested != null) | 
                "  - \(.id): \(.name) - \(.notes // "无备注")"' "$feature_file"
            echo ""
        fi
    fi
    
    # 显示日志信息
    echo -e "${CYAN}日志信息:${NC}"
    echo "------------------------------"
    echo "  主日志:    $LOG_DIR/agent.log"
    echo "  截图目录:  $LOG_DIR/screenshots/"
    echo "  报告目录:  $LOG_DIR/reports/"
    
    local log_size=$(du -sh "$LOG_DIR" 2>/dev/null | cut -f1)
    echo "  日志大小:  $log_size"
    echo ""
}

show_logs() {
    local lines="${1:-50}"
    if [[ -f "$LOG_DIR/agent.log" ]]; then
        echo -e "${CYAN}最近 $lines 行日志:${NC}"
        echo "------------------------------"
        tail -n "$lines" "$LOG_DIR/agent.log"
    else
        echo -e "${YELLOW}暂无日志文件${NC}"
    fi
}

watch_mode() {
    while true; do
        clear
        show_status
        echo "按 Ctrl+C 退出监控"
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
    echo -e "${GREEN}快速报告已生成: $report_file${NC}"
    cat "$report_file"
}

# 主程序
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
        echo "用法:"
        echo "  $0 status    显示当前状态"
        echo "  $0 logs [N]  显示最近N行日志 (默认50)"
        echo "  $0 watch     持续监控模式"
        echo "  $0 report    生成快速报告"
        echo "  $0 help      显示帮助"
        ;;
    *)
        echo "未知命令: $1"
        echo "使用 '$0 help' 查看帮助"
        exit 1
        ;;
esac