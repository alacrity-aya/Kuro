#!/bin/bash
# loop_iflow.sh - 循环运行 iflow 执行多次开发流程
# 用法: ./loop_iflow.sh <次数>

# ============================================
# 配置
# ============================================
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
WORK_DIR="$PROJECT_ROOT"
FRONTEND_DIR="$WORK_DIR/frontend"

# 日志文件
LOG_DIR="$PROJECT_ROOT/logs"
mkdir -p "$LOG_DIR"
MAIN_LOG="$LOG_DIR/loop_$(date +%Y%m%d_%H%M%S).log"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# 循环计数器文件（用于 Ctrl+C 后恢复）
COUNTER_FILE="$LOG_DIR/.loop_counter"

# ============================================
# 信号处理 - 优雅退出
# ============================================
cleanup() {
    echo ""
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW}  收到中断信号，正在保存状态...${NC}"
    echo -e "${YELLOW}========================================${NC}"
    
    # 保存当前进度
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
    echo "长时间运行 Agent 循环脚本"
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
    echo "日志目录: $LOG_DIR"
}

# ============================================
# 获取特征进度
# ============================================
get_feature_progress() {
    local feature_file="$WORK_DIR/agent-harness/feature_list.json"
    if [ -f "$feature_file" ]; then
        if command -v jq &> /dev/null; then
            local total=$(jq 'length' "$feature_file" 2>/dev/null || echo "0")
            local complete=$(jq '[.[] | select(.passes == true)] | length' "$feature_file" 2>/dev/null || echo "0")
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
    echo -e "${BOLD}${CYAN}║${NC}  ${BOLD}会话 $session / $total${NC}"
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
    if [ ! -d "$FRONTEND_DIR" ]; then
        echo -e "${YELLOW}  ⚠ frontend 目录不存在，跳过构建验证${NC}"
        return 0
    fi
    
    echo -e "${CYAN}  🔍 运行构建验证...${NC}"
    
    cd "$FRONTEND_DIR"
    
    # 检查 node_modules
    if [ ! -d "node_modules" ]; then
        echo -e "${YELLOW}  📦 安装依赖...${NC}"
        npm install --silent 2>&1 | tail -5
    fi
    
    # 运行构建
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
# 重置 feature_list.json 中最后一个完成的 feature
# ============================================
reset_last_feature() {
    local feature_file="$WORK_DIR/agent-harness/feature_list.json"
    if [ -f "$feature_file" ] && command -v jq &> /dev/null; then
        # 找到最后一个 passes: true 的 feature 并重置
        jq '(. | map(select(.passes == true)) | last | .passes = false) // empty | . as $last | .[] | if .id == $last.id then .passes = false else . end' "$feature_file" > "${feature_file}.tmp" 2>/dev/null
        if [ -s "${feature_file}.tmp" ]; then
            mv "${feature_file}.tmp" "$feature_file"
            echo -e "${YELLOW}  已重置 feature_list.json 中最后完成的 feature${NC}"
        else
            rm -f "${feature_file}.tmp"
        fi
    fi
}

# ============================================
# 生成 iflow prompt
# ============================================
generate_prompt() {
    cat << 'PROMPT_EOF'
你是 Coding Agent，负责 Kuro 前端项目的开发。

## ⚠️ 关键要求：必须测试通过才能完成

**在你标记任何功能完成之前，必须执行以下验证步骤：**

1. 运行构建：`cd frontend && npm run build`
2. 确保构建成功，没有任何错误
3. 只有构建成功才能继续

**如果构建失败：**
- 修复错误后重新构建
- 不要标记功能为完成
- 不要提交代码

## 启动例行检查 (必须执行)

1. 确认工作目录:
   ```bash
   pwd
   ```

2. 读取进度文件:
   ```bash
   cat agent-harness/claude-progress.txt
   ```

3. 读取功能列表:
   ```bash
   cat agent-harness/feature_list.json
   ```

4. 查看最近的 git 提交:
   ```bash
   git log --oneline -10
   ```

## 工作流程

1. **选择功能**: 从 agent-harness/feature_list.json 中选择优先级最高的未完成功能 (passes: false)

2. **实现功能**: 编写代码，保持简洁聚焦

3. **⚠️ 测试验证 (必须通过), 需要对当前feature的功能和代码的构建进行测试**: 
   ```bash
   cd frontend
   npm install  # 如果需要
   npm run build  # 必须成功！
   ```

4. **提交代码** (仅在测试通过后):
   ```bash
   git add .
   git commit -m "feat: [功能描述]"
   ```

5. **更新功能列表**: 只修改对应功能的 passes 字段为 true

6. **更新进度文件**: 在 agent-harness/claude-progress.txt 追加本次会话记录

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
3. 下一步建议
PROMPT_EOF
}

# ============================================
# 运行单个 iflow 会话
# ============================================
run_iflow_session() {
    local session_num=$1
    local total=$2
    local no_verify=$3
    
    # 显示会话头
    show_session_header "$session_num" "$total" | tee -a "$MAIN_LOG" > /dev/tty
    
    # 会话日志文件
    local session_log="$LOG_DIR/session_${session_num}_$(date +%Y%m%d_%H%M%S).log"
    
    # 生成 prompt
    local prompt=$(generate_prompt)
    
    cd "$WORK_DIR"
    
    local start_time=$(date +%s)
    
    # 记录 session 前的 commit 数量
    local commits_before=$(git rev-list --count HEAD 2>/dev/null || echo "0")
    
    # 运行 iflow - 直接透传输出
    iflow -y \
          --max-tokens 100000 \
          --max-turns 50 \
          -p "$prompt" \
          2>&1 | tee "$session_log"
    
    local exit_code=${PIPESTATUS[0]}
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # 验证阶段
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
    
    # 显示会话尾
    show_session_footer "$duration" "$verified" | tee -a "$MAIN_LOG" > /dev/tty
    
    return 0
}

# ============================================
# 检查是否所有特征完成
# ============================================
check_completion() {
    local feature_file="$WORK_DIR/agent-harness/feature_list.json"
    if [ -f "$feature_file" ] && command -v jq &> /dev/null; then
        local incomplete=$(jq '[.[] | select(.passes == false)] | length' "$feature_file" 2>/dev/null || echo "1")
        if [ "$incomplete" -eq 0 ]; then
            return 0  # 所有特征完成
        fi
    fi
    return 1  # 还有未完成的特征
}

# ============================================
# 主程序
# ============================================

# 解析参数
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

# 如果没有指定循环次数
if [ -z "$ITERATIONS" ]; then
    echo "错误: 请指定循环次数"
    show_help
    exit 1
fi

# 恢复或初始化计数器
if [ "$RESUME" = true ] && [ -f "$COUNTER_FILE" ]; then
    START_ITERATION=$(($(cat "$COUNTER_FILE") + 1))
    echo -e "${GREEN}从上次中断处恢复，从第 $START_ITERATION 次开始${NC}"
else
    START_ITERATION=1
fi

# 开始
echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║${NC}     ${BOLD}Kuro 前端开发 - Long Running Agent${NC}"
echo -e "${BOLD}${BLUE}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}${BLUE}║${NC}  循环次数: $ITERATIONS"
echo -e "${BOLD}${BLUE}║${NC}  工作目录: $WORK_DIR"
echo -e "${BOLD}${BLUE}║${NC}  日志目录: $LOG_DIR"
echo -e "${BOLD}${BLUE}║${NC}  验证模式: $([ "$NO_VERIFY" = true ] && echo "关闭" || echo "开启")"
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# 主循环
CURRENT_ITERATION=$START_ITERATION
for i in $(seq "$START_ITERATION" "$ITERATIONS"); do
    CURRENT_ITERATION=$i
    
    run_iflow_session "$i" "$ITERATIONS" "$NO_VERIFY"
    
    # 检查是否所有特征都完成了
    if check_completion; then
        echo ""
        echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}  🎉 所有功能已完成！提前结束循环。${NC}"
        echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
        rm -f "$COUNTER_FILE"
        exit 0
    fi
    
    # 如果不是最后一次，显示分隔
    if [ "$i" -lt "$ITERATIONS" ]; then
        echo ""
        echo -e "${YELLOW}>>> 等待 3 秒后开始下一个会话... (Ctrl+C 可安全中断)${NC}"
        sleep 3
    fi
done

# 结束
echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║${NC}     ${BOLD}循环执行完成！${NC}"
echo -e "${BOLD}${GREEN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}${GREEN}║${NC}  总执行次数: $ITERATIONS"
echo -e "${BOLD}${GREEN}║${NC}  最终进度: $(get_feature_progress)"
echo -e "${BOLD}${GREEN}║${NC}  日志目录: $LOG_DIR"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# 清理计数器文件
rm -f "$COUNTER_FILE"
