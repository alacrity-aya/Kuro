#!/bin/bash
# run-metrics-agent-loop.sh - 循环运行 Metrics 页面开发
# 用法: ./run-metrics-agent-loop.sh <次数>

# ============================================
# 配置
# ============================================
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
WORK_DIR="$PROJECT_ROOT"
FRONTEND_DIR="$WORK_DIR/frontend"

# 使用 metrics 功能列表
FEATURE_FILE="$WORK_DIR/agent-harness/metrics-feature-list.json"

# 日志文件
LOG_DIR="$PROJECT_ROOT/logs"
mkdir -p "$LOG_DIR"
MAIN_LOG="$LOG_DIR/metrics_loop_$(date +%Y%m%d_%H%M%S).log"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# 循环计数器文件
COUNTER_FILE="$LOG_DIR/.metrics_loop_counter"

# ============================================
# 信号处理 - 优雅退出
# ============================================
cleanup() {
    echo ""
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW}  收到中断信号，正在保存状态...${NC}"
    echo -e "${YELLOW}========================================${NC}"
    
    echo "$CURRENT_ITERATION" > "$COUNTER_FILE"
    
    echo -e "${GREEN}状态已保存。下次运行将从第 $((CURRENT_ITERATION + 1)) 次继续。${NC}"
    echo -e "${CYAN}日志目录: $LOG_DIR${NC}"
    exit 0
}

trap cleanup SIGINT SIGTERM

# ============================================
# 帮助信息
# ============================================
show_help() {
    echo "Metrics 页面开发循环脚本"
    echo ""
    echo "用法: $0 <循环次数>"
    echo ""
    echo "参数:"
    echo "  循环次数    执行 iflow 的次数"
    echo ""
    echo "示例:"
    echo "  $0 10    # 运行 10 次"
    echo "  $0 5     # 运行 5 次"
    echo ""
    echo "选项:"
    echo "  -h, --help    显示帮助信息"
    echo "  --resume      从上次中断处继续"
    echo "  --no-verify   跳过测试验证"
    echo ""
    echo "功能列表: agent-harness/metrics-feature-list.json"
    echo "日志目录: $LOG_DIR"
}

# ============================================
# 获取特征进度
# ============================================
get_feature_progress() {
    if [ -f "$FEATURE_FILE" ]; then
        if command -v jq &> /dev/null; then
            local total=$(jq '.features | length' "$FEATURE_FILE" 2>/dev/null || echo "0")
            local complete=$(jq '[.features[] | select(.passes == true)] | length' "$FEATURE_FILE" 2>/dev/null || echo "0")
            local incomplete=$((total - complete))
            echo "$complete/$total 完成, $incomplete 待完成"
        else
            echo "(安装 jq 查看详情)"
        fi
    else
        echo "未初始化"
    fi
}

# ============================================
# 显示会话开始信息
# ============================================
show_session_header() {
    local session=$1
    local total=$2
    
    echo ""
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║${NC}  ${BOLD}Metrics 开发会话 $session / $total${NC}"
    echo -e "${BOLD}${CYAN}╠══════════════════════════════════════════════════╣${NC}"
    echo -e "${BOLD}${CYAN}║${NC}  进度: $(get_feature_progress)"
    echo -e "${BOLD}${CYAN}║${NC}  目录: $WORK_DIR"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ============================================
# 显示会话结束信息
# ============================================
show_session_footer() {
    local duration=$1
    local verified=$2
    
    echo ""
    if [ "$verified" = "true" ]; then
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${GREEN}  ✅ 会话完成并通过验证，耗时: ${duration} 秒${NC}"
        echo -e "${GREEN}  进度: $(get_feature_progress)${NC}"
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    else
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${RED}  ❌ 会话完成但验证失败，耗时: ${duration} 秒${NC}"
        echo -e "${RED}  已回滚本次提交${NC}"
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    fi
}

# ============================================
# 验证构建
# ============================================
verify_build() {
    echo -e "${CYAN}  🔍 运行构建验证...${NC}"
    
    cd "$FRONTEND_DIR"
    
    if [ ! -d "node_modules" ]; then
        echo -e "${YELLOW}  📦 安装依赖...${NC}"
        npm install --silent 2>&1 | tail -5
    fi
    
    echo -e "${CYAN}  🏗 执行 npm run build...${NC}"
    if npm run build 2>&1; then
        echo -e "${GREEN}  ✅ 构建成功${NC}"
        return 0
    else
        echo -e "${RED}  ❌ 构建失败${NC}"
        return 1
    fi
}

# ============================================
# 回滚最后一次提交
# ============================================
rollback_last_commit() {
    echo -e "${YELLOW}  ⏪ 回滚最后一次提交...${NC}"
    cd "$WORK_DIR"
    git reset --hard HEAD~1 2>/dev/null
    echo -e "${YELLOW}  已回滚${NC}"
}

# ============================================
# 重置最后一个完成的 feature
# ============================================
reset_last_feature() {
    if [ -f "$FEATURE_FILE" ] && command -v jq &> /dev/null; then
        jq '(.features | map(select(.passes == true)) | last | .passes = false) // empty | . as $last | .features |= map(if .id == $last.id then .passes = false else . end)' "$FEATURE_FILE" > "${FEATURE_FILE}.tmp" 2>/dev/null
        if [ -s "${FEATURE_FILE}.tmp" ]; then
            mv "${FEATURE_FILE}.tmp" "$FEATURE_FILE"
            echo -e "${YELLOW}  已重置 metrics-feature-list.json 中最后完成的 feature${NC}"
        else
            rm -f "${FEATURE_FILE}.tmp"
        fi
    fi
}

# ============================================
# 生成 iflow prompt
# ============================================
generate_prompt() {
    cat << 'PROMPT_EOF'
你是 Coding Agent，负责 Kuro 前端 Metrics 监控页面的开发。

## ⚠️ 关键要求：必须测试通过才能完成

**在你标记任何功能完成之前，必须执行以下验证步骤：**

1. 运行构建：`cd frontend && npm run build`
2. 确保构建成功，没有任何错误
3. 只有构建成功才能继续

**如果构建失败：**
- 修复错误后重新构建
- 不要标记功能为完成
- 不要提交代码

## 重要约束

### ⚠️ 后端约束
- **不修改后端代码**
- 所有需要后端 API 的地方，使用 `frontend/src/api/mock.ts` 中的 mock 函数
- 在代码注释中明确标注 `// TODO: 需要后端 API - GET /api/v1/metrics/xxx`

## 启动例行检查 (必须执行)

1. 确认工作目录:
   ```bash
   pwd
   ```

2. 读取功能列表:
   ```bash
   cat agent-harness/metrics-feature-list.json
   ```

3. 读取开发指南:
   ```bash
   cat agent-harness/metrics-agent-prompt.md
   ```

4. 查看现有的 metrics 组件:
   ```bash
   ls -la frontend/src/components/metrics/
   cat frontend/src/api/mock.ts | grep -A 30 "Mock Metrics"
   ```

5. 查看最近的 git 提交:
   ```bash
   git log --oneline -5
   ```

## 工作流程

1. **选择功能**: 从 agent-harness/metrics-feature-list.json 中选择优先级最高的未完成功能 (passes: false)

2. **阅读指南**: 参考 agent-harness/metrics-agent-prompt.md 中的实现指南

3. **实现功能**: 编写代码，保持简洁聚焦

4. **⚠️ 测试验证 (必须通过)**: 
   ```bash
   cd frontend
   npm install  # 如果需要
   npm run build  # 必须成功！
   ```

5. **提交代码** (仅在测试通过后):
   ```bash
   git add .
   git commit -m "feat(metrics): [功能描述] (METRICS-xxx)"
   ```

6. **更新功能列表**: 只修改对应功能的 passes 字段为 true

## 开发顺序建议

按以下顺序实现功能：

### Phase 1: 基础设施
- METRICS-013: Mock Metrics API
- METRICS-014: useMetrics Hook

### Phase 2: 页面布局
- METRICS-001: Metrics Dashboard Page Layout
- METRICS-009: Time Range Selector
- METRICS-010: Auto Refresh
- METRICS-008: Topology Selector

### Phase 3: 图表组件
- METRICS-002: Topology Summary Cards
- METRICS-003: Bandwidth Overview Chart
- METRICS-004: Latency Distribution Chart
- METRICS-005: Packet Loss Gauge Panel

### Phase 4: 表格和集成
- METRICS-006: Node Metrics Table
- METRICS-007: Link Metrics Table
- METRICS-012: Alerts Panel
- METRICS-015: Metrics Page Integration

## 重要规则

- 🚫 **构建失败 = 功能未完成**
- 每个会话只处理一个功能
- 永远不要删除或修改功能描述
- 所有 API 使用 mock 数据
- 离开时确保环境干净

## 会话结束

输出会话摘要：
1. 完成的工作
2. 构建验证结果（成功/失败）
3. 更新的文件列表
4. 下一步建议
PROMPT_EOF
}

# ============================================
# 运行单个 iflow 会话
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
        echo -e "${BOLD}${BLUE}  验证阶段${NC}"
        echo -e "${BOLD}${BLUE}═════════════════════════════════════════════════${NC}"
        
        if ! verify_build; then
            verified="false"
            echo ""
            echo -e "${RED}  ❌ 验证失败，回滚更改...${NC}"
            rollback_last_commit
            reset_last_feature
        fi
    fi
    
    show_session_footer "$duration" "$verified" | tee -a "$MAIN_LOG" > /dev/tty
    
    return 0
}

# ============================================
# 检查是否所有特征完成
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
# 主程序
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
    echo "错误: 请指定循环次数"
    show_help
    exit 1
fi

if [ "$RESUME" = true ] && [ -f "$COUNTER_FILE" ]; then
    START_ITERATION=$(($(cat "$COUNTER_FILE") + 1))
    echo -e "${GREEN}从上次中断处恢复，从第 $START_ITERATION 次开始${NC}"
else
    START_ITERATION=1
fi

echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║${NC}     ${BOLD}Kuro Metrics 页面开发 - Long Running Agent${NC}"
echo -e "${BOLD}${BLUE}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}${BLUE}║${NC}  循环次数: $ITERATIONS"
echo -e "${BOLD}${BLUE}║${NC}  工作目录: $WORK_DIR"
echo -e "${BOLD}${BLUE}║${NC}  功能列表: agent-harness/metrics-feature-list.json"
echo -e "${BOLD}${BLUE}║${NC}  日志目录: $LOG_DIR"
echo -e "${BOLD}${BLUE}║${NC}  验证模式: $([ "$NO_VERIFY" = true ] && echo "关闭" || echo "开启")"
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════╝${NC}"
echo ""

CURRENT_ITERATION=$START_ITERATION
for i in $(seq "$START_ITERATION" "$ITERATIONS"); do
    CURRENT_ITERATION=$i
    
    run_iflow_session "$i" "$ITERATIONS" "$NO_VERIFY"
    
    if check_completion; then
        echo ""
        echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}  🎉 所有 Metrics 功能已完成！提前结束循环。${NC}"
        echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
        rm -f "$COUNTER_FILE"
        exit 0
    fi
    
    if [ "$i" -lt "$ITERATIONS" ]; then
        echo ""
        echo -e "${YELLOW}>>> 等待 3 秒后开始下一个会话... (Ctrl+C 可安全中断)${NC}"
        sleep 3
    fi
done

echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║${NC}     ${BOLD}循环执行完成！${NC}"
echo -e "${BOLD}${GREEN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}${GREEN}║${NC}  总执行次数: $ITERATIONS"
echo -e "${BOLD}${GREEN}║${NC}  最终进度: $(get_feature_progress)"
echo -e "${BOLD}${GREEN}║${NC}  日志目录: $LOG_DIR"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

rm -f "$COUNTER_FILE"
