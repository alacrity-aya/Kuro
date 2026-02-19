#!/bin/bash
# run-test-agent-loop.sh - Long Running Test Agent 循环脚本
# 用法: ./run-test-agent-loop.sh <次数>
#
# 该脚本循环运行 iflow Test Agent，对每个 feature 进行：
# 1. 代码层面测试（类型检查、单元测试、构建）
# 2. 浏览器 E2E 测试（使用 MCP 工具）

# ============================================
# 配置
# ============================================
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
WORK_DIR="$PROJECT_ROOT"
FRONTEND_DIR="$WORK_DIR/frontend"
AGENT_HARNESS_DIR="$WORK_DIR/agent-harness"

# 日志文件
LOG_DIR="$PROJECT_ROOT/logs"
SCREENSHOT_DIR="$LOG_DIR/screenshots"
mkdir -p "$LOG_DIR"
mkdir -p "$SCREENSHOT_DIR"
TEST_LOG="$LOG_DIR/test-loop_$(date +%Y%m%d_%H%M%S).log"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# 循环计数器文件（用于 Ctrl+C 后恢复）
COUNTER_FILE="$LOG_DIR/.test_loop_counter"
TESTED_FEATURES_FILE="$LOG_DIR/.tested_features"

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
    echo -e "${CYAN}截图目录: $SCREENSHOT_DIR${NC}"
    
    # 停止开发服务器
    if [ -n "$DEV_SERVER_PID" ]; then
        echo -e "${YELLOW}停止开发服务器 (PID: $DEV_SERVER_PID)...${NC}"
        kill "$DEV_SERVER_PID" 2>/dev/null
    fi
    
    exit 0
}

trap cleanup SIGINT SIGTERM

# ============================================
# 帮助信息
# ============================================
show_help() {
    echo "Long Running Test Agent 循环脚本"
    echo ""
    echo "用法: $0 <循环次数>"
    echo ""
    echo "参数:"
    echo "  循环次数    执行测试的迭代次数"
    echo ""
    echo "示例:"
    echo "  $0 10    # 运行 10 次测试迭代"
    echo "  $0 5     # 运行 5 次测试迭代"
    echo ""
    echo "选项:"
    echo "  -h, --help       显示帮助信息"
    echo "  --resume         从上次中断处继续"
    echo "  --no-browser     跳过浏览器测试（只运行代码测试）"
    echo "  --feature <id>   只测试特定 feature (如: FEAT-015)"
    echo ""
    echo "日志目录: $LOG_DIR"
    echo "截图目录: $SCREENSHOT_DIR"
}

# ============================================
# 获取测试进度
# ============================================
get_test_progress() {
    local feature_file="$AGENT_HARNESS_DIR/test-feature-list.json"
    if [ -f "$feature_file" ]; then
        if command -v jq &> /dev/null; then
            local total=$(jq '.features | length' "$feature_file" 2>/dev/null || echo "0")
            local passed=$(jq '[.features[] | select(.passes == true)] | length' "$feature_file" 2>/dev/null || echo "0")
            local failed=$(jq '[.features[] | select(.passes == false and .lastTested != null)] | length' "$feature_file" 2>/dev/null || echo "0")
            local pending=$((total - passed - failed))
            echo "✅ $passed 通过, ❌ $failed 失败, ⏳ $pending 待测 / 共 $total"
        else
            echo "(安装 jq 查看详情)"
        fi
    else
        echo "测试清单未找到"
    fi
}

# ============================================
# 获取下一个待测 feature
# 优先级: 1. 之前失败过的 (passes=false, lastTested!=null, retryCount<max)
#         2. 从未测试过的 (passes=false, lastTested=null)
# ============================================
get_next_feature() {
    local feature_file="$AGENT_HARNESS_DIR/test-feature-list.json"
    if [ -f "$feature_file" ] && command -v jq &> /dev/null; then
        # 首先获取之前测试过但失败的（需要重试的）
        local failed_feature=$(jq -r '.features[] | select(.passes == false and .lastTested != null and (.retryCount // 0) < 3) | .id' "$feature_file" 2>/dev/null | head -1)
        if [ -n "$failed_feature" ] && [ "$failed_feature" != "null" ]; then
            echo "$failed_feature"
            return
        fi
        # 然后获取从未测试过的
        jq -r '.features[] | select(.passes == false and .lastTested == null) | .id' "$feature_file" 2>/dev/null | head -1
    fi
}

# ============================================
# 显示会话开始信息
# ============================================
show_session_header() {
    local session=$1
    local total=$2
    local feature_id=$3
    local feature_name=$4
    
    echo ""
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║${NC}  ${BOLD}测试会话 $session / $total${NC}"
    echo -e "${BOLD}${CYAN}╠══════════════════════════════════════════════════╣${NC}"
    echo -e "${BOLD}${CYAN}║${NC}  功能: ${YELLOW}$feature_id${NC}"
    echo -e "${BOLD}${CYAN}║${NC}  名称: $feature_name"
    echo -e "${BOLD}${CYAN}║${NC}  进度: $(get_test_progress)"
    echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ============================================
# 显示会话结束信息
# ============================================
show_session_footer() {
    local duration=$1
    local passed=$2
    local feature_id=$3
    
    echo ""
    if [ "$passed" = "true" ]; then
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${GREEN}  ✅ $feature_id 测试通过，耗时: ${duration} 秒${NC}"
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    else
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${RED}  ❌ $feature_id 测试失败，耗时: ${duration} 秒${NC}"
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    fi
}

# ============================================
# 启动开发服务器
# ============================================
start_dev_server() {
    echo -e "${CYAN}  🚀 启动开发服务器...${NC}"
    
    cd "$FRONTEND_DIR"
    
    # 检查 node_modules
    if [ ! -d "node_modules" ]; then
        echo -e "${YELLOW}  📦 安装依赖...${NC}"
        npm install --silent 2>&1 | tail -5
    fi
    
    # 启动开发服务器
    npm run dev > "$LOG_DIR/dev-server.log" 2>&1 &
    DEV_SERVER_PID=$!
    
    # 等待服务器启动
    echo -e "${CYAN}  ⏳ 等待服务器启动...${NC}"
    local retries=0
    local max_retries=30
    
    while [ $retries -lt $max_retries ]; do
        if curl -s http://localhost:5173 > /dev/null 2>&1; then
            echo -e "${GREEN}  ✅ 开发服务器已启动 (PID: $DEV_SERVER_PID)${NC}"
            return 0
        fi
        sleep 1
        retries=$((retries + 1))
    done
    
    echo -e "${RED}  ❌ 开发服务器启动超时${NC}"
    return 1
}

# ============================================
# 停止开发服务器
# ============================================
stop_dev_server() {
    if [ -n "$DEV_SERVER_PID" ]; then
        echo -e "${CYAN}  🛑 停止开发服务器...${NC}"
        kill "$DEV_SERVER_PID" 2>/dev/null
        wait "$DEV_SERVER_PID" 2>/dev/null
        DEV_SERVER_PID=""
    fi
}

# ============================================
# 代码层面测试
# ============================================
run_code_tests() {
    echo ""
    echo -e "${BOLD}${BLUE}═════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  阶段 1: 代码层面测试${NC}"
    echo -e "${BOLD}${BLUE}═════════════════════════════════════════════════${NC}"
    
    cd "$FRONTEND_DIR"
    
    # 1. 类型检查
    echo -e "${CYAN}  🔍 运行 TypeScript 类型检查...${NC}"
    if npx tsc --noEmit 2>&1; then
        echo -e "${GREEN}  ✅ 类型检查通过${NC}"
    else
        echo -e "${RED}  ❌ 类型检查失败${NC}"
        return 1
    fi
    
    # 2. 单元测试
    echo -e "${CYAN}  🧪 运行单元测试...${NC}"
    if npm run test:run 2>&1; then
        echo -e "${GREEN}  ✅ 单元测试通过${NC}"
    else
        echo -e "${RED}  ❌ 单元测试失败${NC}"
        return 1
    fi
    
    # 3. 构建验证
    echo -e "${CYAN}  🏗 运行生产构建...${NC}"
    if npm run build 2>&1; then
        echo -e "${GREEN}  ✅ 构建成功${NC}"
    else
        echo -e "${RED}  ❌ 构建失败${NC}"
        return 1
    fi
    
    return 0
}

# ============================================
# 生成 iflow prompt
# ============================================
generate_test_prompt() {
    local feature_id=$1
    local feature_name=$2
    local category=$3
    
    cat << PROMPT_EOF
你是 Kuro 前端项目的 **Test Agent**。你的任务是执行功能测试，包括代码测试和浏览器 E2E 测试。

## 当前测试任务

**功能 ID**: $feature_id
**功能名称**: $feature_name
**类别**: $category

## Session 启动流程

### Step 1: 确认工作目录
\`\`\`bash
pwd
\`\`\`

### Step 2: 阅读测试清单
读取 \`agent-harness/test-feature-list.json\` 了解当前功能的详细测试步骤。

### Step 3: 检查开发服务器
开发服务器应该已经在 http://localhost:5173 运行，验证是否可以访问：
\`\`\`bash
curl -s http://localhost:5173 > /dev/null && echo "服务器运行中" || echo "服务器未启动"
\`\`\`

## 测试阶段

### 阶段 1: 代码层面测试（已完成外部验证）

### 阶段 2: 浏览器 E2E 测试（你的主要任务）

使用 MCP 浏览器工具进行以下测试：

1. **browser_navigate** - 访问被测页面
2. **browser_wait_for** - 等待页面加载
3. **browser_take_screenshot** - 截取关键状态截图
4. **browser_click** - 执行用户交互
5. **browser_evaluate** - 验证页面状态

**截图要求**:
- 保存到: logs/screenshots/${feature_id}_\$(date +%Y%m%d_%H%M%S).png
- 至少 2 张：初始状态 + 关键操作后

**验证要点**:
- 页面元素正确渲染
- 交互功能正常工作
- 无 console.error 错误

## 测试报告

测试完成后，输出：
1. 测试通过/失败状态
2. 发现的问题（如有）
3. 截图文件路径

## 更新测试清单

如果测试通过：
\`\`\`bash
# 更新 feature_list.json 中的 passes 为 true
# 添加 lastTested 时间戳
\`\`\`

如果测试失败：
\`\`\`bash
# 更新 lastTested 时间戳
# 在 notes 字段添加失败原因
\`\`\`

## 重要规则

- 每个测试步骤都要有明确的验证点
- 发现问题立即记录
- 截图是测试通过的必要证据
- 不要修改被测功能的代码
PROMPT_EOF
}

# ============================================
# 生成修复 agent prompt
# ============================================
generate_fix_prompt() {
    local feature_id=$1
    local feature_name=$2
    local category=$3
    local failure_reason=$4
    
    cat << PROMPT_EOF
你是 Kuro 前端项目的 **Fix Agent**。你的任务是修复测试失败的功能，直到测试通过。

## 当前修复任务

**功能 ID**: $feature_id
**功能名称**: $feature_name
**类别**: $category
**失败原因**: $failure_reason

## 修复流程

### Step 1: 了解功能需求
读取 \\\`agent-harness/test-feature-list.json\\\` 了解该功能的详细描述和测试步骤。

### Step 2: 查看现有代码
找到与该功能相关的代码文件，理解当前实现。

### Step 3: 运行测试验证失败
运行代码测试确认失败：
\\\`\\\`\\\`bash
cd frontend
npx tsc --noEmit
npm run test:run
npm run build
\\\`\\\`\\\`

### Step 4: 分析问题并修复
根据失败原因，修复代码中的问题。可能的问题包括：
- TypeScript 类型错误
- 单元测试失败
- 构建错误
- 组件渲染问题
- 逻辑错误

### Step 5: 验证修复
修复后再次运行测试：
\\\`\\\`\\\`bash
cd frontend
npx tsc --noEmit
npm run test:run
npm run build
\\\`\\\`\\\`

### Step 6: 更新测试清单
如果修复成功，更新 \\\`agent-harness/test-feature-list.json\\\`：
- 将 \\\`passes\\\` 改为 \\\`true\\\`
- 添加 \\\`lastTested\\\` 时间戳
- 清空 \\\`notes\\\`
- 重置 \\\`retryCount\\\` 为 0

如果修复失败：
- 增加 \\\`retryCount\\\`
- 在 \\\`notes\\\` 中记录修复尝试和剩余问题

## 重要规则

- 只修改必要的代码来修复问题
- 保持代码风格和项目一致性
- 修复后必须验证测试通过
- 如果无法修复，详细记录问题原因
PROMPT_EOF
}

# ============================================
# 更新 feature 重试计数
# ============================================
update_retry_count() {
    local feature_id=$1
    local feature_file="$AGENT_HARNESS_DIR/test-feature-list.json"
    
    if [ -f "$feature_file" ] && command -v jq &> /dev/null; then
        local current_count=$(jq -r --arg id "$feature_id" '.features[] | select(.id == $id) | (.retryCount // 0)' "$feature_file" 2>/dev/null)
        local new_count=$((current_count + 1))
        
        # 使用 jq 更新 retryCount
        local temp_file=$(mktemp)
        jq --arg id "$feature_id" --argjson count "$new_count" '
            .features = [.features[] | if .id == $id then .retryCount = $count else . end]
        ' "$feature_file" > "$temp_file" && mv "$temp_file" "$feature_file"
    fi
}

# ============================================
# 重置 feature 重试计数
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
# 运行修复 agent
# ============================================
run_fix_agent() {
    local feature_id=$1
    local feature_name=$2
    local category=$3
    local failure_reason=$4
    
    echo ""
    echo -e "${BOLD}${YELLOW}═════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${YELLOW}  启动修复 Agent${NC}"
    echo -e "${BOLD}${YELLOW}═════════════════════════════════════════════════${NC}"
    
    # 生成修复 prompt
    local prompt=$(generate_fix_prompt "$feature_id" "$feature_name" "$category" "$failure_reason")
    
    # 运行 iflow Fix Agent
    echo -e "${CYAN}  🔧 启动 Fix Agent 进行修复...${NC}"
    cd "$WORK_DIR"
    
    local fix_log="$LOG_DIR/fix-session_${feature_id}_$(date +%Y%m%d_%H%M%S).log"
    
    iflow -y \
          --max-tokens 100000 \
          --max-turns 100 \
          -p "$prompt" \
          2>&1 | tee "$fix_log"
    
    local iflow_exit_code=${PIPESTATUS[0]}
    
    if [ $iflow_exit_code -ne 0 ]; then
        echo -e "${YELLOW}  ⚠ Fix Agent 异常退出 (code: $iflow_exit_code)${NC}"
    fi
    
    echo -e "${GREEN}  ✅ 修复 Agent 完成${NC}"
    echo -e "${CYAN}  📝 修复日志: $fix_log${NC}"
}

# ============================================
# 运行单个测试会话
# ============================================

run_test_session() {
    local session_num=$1
    local total=$2
    local feature_id=$3
    local no_browser=$4
    
    # 获取 feature 信息
    local feature_file="$AGENT_HARNESS_DIR/test-feature-list.json"
    local feature_name=""
    local category=""
    
    if [ -f "$feature_file" ] && command -v jq &> /dev/null; then
        feature_name=$(jq -r --arg id "$feature_id" '.features[] | select(.id == $id) | .name' "$feature_file" 2>/dev/null)
        category=$(jq -r --arg id "$feature_id" '.features[] | select(.id == $id) | .category' "$feature_file" 2>/dev/null)
    fi
    
    if [ -z "$feature_name" ]; then
        echo -e "${RED}错误: 找不到 feature $feature_id${NC}"
        return 1
    fi
    
    # 显示会话头
    show_session_header "$session_num" "$total" "$feature_id" "$feature_name" | tee -a "$TEST_LOG" > /dev/tty
    
    local session_log="$LOG_DIR/test-session_${session_num}_${feature_id}_$(date +%Y%m%d_%H%M%S).log"
    local start_time=$(date +%s)
    local test_passed="true"
    
    # ============================================
    # 阶段 1: 代码测试
    # ============================================
    if ! run_code_tests 2>&1 | tee -a "$TEST_LOG"; then
        test_passed="false"
        echo -e "${RED}  ❌ 代码测试失败${NC}"
    fi
    
    # ============================================
    # 阶段 2: 浏览器测试
    # ============================================
    if [ "$test_passed" = "true" ] && [ "$no_browser" != "true" ]; then
        echo ""
        echo -e "${BOLD}${BLUE}═════════════════════════════════════════════════${NC}"
        echo -e "${BOLD}${BLUE}  阶段 2: 浏览器 E2E 测试${NC}"
        echo -e "${BOLD}${BLUE}═════════════════════════════════════════════════${NC}"
        
        if [ -z "$DEV_SERVER_PID" ]; then
            start_dev_server || test_passed="false"
        fi
        
        if [ "$test_passed" = "true" ]; then
            local prompt=$(generate_test_prompt "$feature_id" "$feature_name" "$category")
            
            echo -e "${CYAN}  🤖 启动 Test Agent 进行浏览器测试...${NC}"
            cd "$WORK_DIR"
            
            iflow -y \
                  --max-tokens 100000 \
                  --max-turns 100 \
                  -p "$prompt" \
                  2>&1 | tee "$session_log"
            
            local iflow_exit_code=${PIPESTATUS[0]}
            
            if [ $iflow_exit_code -ne 0 ]; then
                echo -e "${YELLOW}  ⚠ Test Agent 异常退出 (code: $iflow_exit_code)${NC}"
            fi
            
            # 检查 feature 是否通过
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
    # 自动修复逻辑
    # ============================================
    if [ "$test_passed" != "true" ]; then
        echo ""
        echo -e "${YELLOW}⚠ 检测到测试失败，启动修复流程...${NC}"
        
        local failure_reason="测试失败"
        if [ -f "$feature_file" ] && command -v jq &> /dev/null; then
            failure_reason=$(jq -r --arg id "$feature_id" \
                '.features[] | select(.id == $id) | .notes // "测试失败，未提供详细原因"' \
                "$feature_file" 2>/dev/null)
        fi
        
        # 最多尝试 3 次修复
        for attempt in 1 2 3; do
            echo -e "${YELLOW}🔧 修复尝试 #$attempt${NC}"
            
            run_fix_agent "$feature_id" "$feature_name" "$category" "$failure_reason"
            
            echo -e "${CYAN}🔁 修复后重新验证代码测试...${NC}"
            
            if run_code_tests; then
                echo -e "${GREEN}✅ 修复后代码测试通过${NC}"
                
                # 再次检查 passes 状态
                if [ -f "$feature_file" ] && command -v jq &> /dev/null; then
                    local feature_passed_after_fix=$(jq -r --arg id "$feature_id" \
                        '.features[] | select(.id == $id) | .passes' \
                        "$feature_file" 2>/dev/null)
                        
                    if [ "$feature_passed_after_fix" = "true" ]; then
                        echo -e "${GREEN}🎉 修复成功${NC}"
                        reset_retry_count "$feature_id"
                        test_passed="true"
                        break
                    fi
                fi
            else
                echo -e "${RED}❌ 修复后代码测试仍失败${NC}"
            fi
        done
        
        if [ "$test_passed" != "true" ]; then
            echo -e "${RED}❌ 多次修复尝试后仍失败${NC}"
            update_retry_count "$feature_id"
        fi
    else
        reset_retry_count "$feature_id"
    fi
    
    echo "$feature_id" >> "$TESTED_FEATURES_FILE"
    
    return 0
}


# ============================================
# 检查是否所有 feature 测试完成
# ============================================
check_all_tested() {
    local feature_file="$AGENT_HARNESS_DIR/test-feature-list.json"
    if [ -f "$feature_file" ] && command -v jq &> /dev/null; then
        local untested=$(jq '[.features[] | select(.passes == false and .lastTested == null)] | length' "$feature_file" 2>/dev/null || echo "1")
        if [ "$untested" -eq 0 ]; then
            return 0  # 所有 feature 已测试
        fi
    fi
    return 1  # 还有未测试的 feature
}

# ============================================
# 生成测试报告
# ============================================
generate_report() {
    local feature_file="$AGENT_HARNESS_DIR/test-feature-list.json"
    
    echo ""
    echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${BLUE}║${NC}           ${BOLD}测试报告${NC}"
    echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
    
    if [ -f "$feature_file" ] && command -v jq &> /dev/null; then
        echo "功能测试状态:"
        echo ""
        
        jq -r '.features[] | "\(.id): \(.name) - \(.passes | if . then "✅ 通过" else "❌ 待测" end)"' "$feature_file" 2>/dev/null | while read line; do
            echo "  $line"
        done
        
        echo ""
        local total=$(jq '.features | length' "$feature_file" 2>/dev/null)
        local passed=$(jq '[.features[] | select(.passes == true)] | length' "$feature_file" 2>/dev/null)
        local percentage=$((passed * 100 / total))
        
        echo "总计: $passed / $total 通过 ($percentage%)"
    fi
    
    echo ""
    echo "日志文件: $TEST_LOG"
    echo "截图目录: $SCREENSHOT_DIR"
    echo ""
}

# ============================================
# 主程序
# ============================================

# 解析参数
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

# 如果没有指定循环次数且不是单功能测试
if [ -z "$ITERATIONS" ] && [ -z "$SINGLE_FEATURE" ]; then
    echo "错误: 请指定循环次数或使用 --feature 指定单个功能"
    show_help
    exit 1
fi

# 单功能测试模式
if [ -n "$SINGLE_FEATURE" ]; then
    echo ""
    echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${BLUE}║${NC}     ${BOLD}Kuro 前端测试 - 单功能模式${NC}"
    echo -e "${BOLD}${BLUE}╠══════════════════════════════════════════════════╣${NC}"
    echo -e "${BOLD}${BLUE}║${NC}  功能: $SINGLE_FEATURE"
    echo -e "${BOLD}${BLUE}║${NC}  浏览器测试: $([ "$NO_BROWSER" = true ] && echo "跳过" || echo "启用")"
    echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
    
    run_test_session 1 1 "$SINGLE_FEATURE" "$NO_BROWSER"
    generate_report
    stop_dev_server
    exit 0
fi

# 恢复或初始化计数器
if [ "$RESUME" = true ] && [ -f "$COUNTER_FILE" ]; then
    START_ITERATION=$(($(cat "$COUNTER_FILE") + 1))
    echo -e "${GREEN}从上次中断处恢复，从第 $START_ITERATION 次开始${NC}"
else
    START_ITERATION=1
    # 清空已测试记录
    rm -f "$TESTED_FEATURES_FILE"
fi

# 启动信息
echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║${NC}     ${BOLD}Kuro 前端测试 - Long Running Test Agent${NC}"
echo -e "${BOLD}${BLUE}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}${BLUE}║${NC}  循环次数: $ITERATIONS"
echo -e "${BOLD}${BLUE}║${NC}  工作目录: $WORK_DIR"
echo -e "${BOLD}${BLUE}║${NC}  日志目录: $LOG_DIR"
echo -e "${BOLD}${BLUE}║${NC}  截图目录: $SCREENSHOT_DIR"
echo -e "${BOLD}${BLUE}║${NC}  浏览器测试: $([ "$NO_BROWSER" = true ] && echo "跳过" || echo "启用")"
echo -e "${BOLD}${BLUE}║${NC}  当前进度: $(get_test_progress)"
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# 主循环
CURRENT_ITERATION=$START_ITERATION
for i in $(seq "$START_ITERATION" "$ITERATIONS"); do
    CURRENT_ITERATION=$i
    
    # 获取下一个待测 feature
    FEATURE_ID=$(get_next_feature)
    
    if [ -z "$FEATURE_ID" ]; then
        echo ""
        echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}  🎉 所有功能已测试完成！提前结束循环。${NC}"
        echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
        break
    fi
    
    run_test_session "$i" "$ITERATIONS" "$FEATURE_ID" "$NO_BROWSER"
    
    # 如果不是最后一次，显示分隔
    if [ "$i" -lt "$ITERATIONS" ]; then
        echo ""
        echo -e "${YELLOW}>>> 等待 5 秒后开始下一个测试... (Ctrl+C 可安全中断)${NC}"
        sleep 5
    fi
done

# 停止开发服务器
stop_dev_server

# 生成报告
generate_report

# 结束
echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║${NC}     ${BOLD}测试循环执行完成！${NC}"
echo -e "${BOLD}${GREEN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}${GREEN}║${NC}  总执行次数: $((CURRENT_ITERATION - START_ITERATION + 1))"
echo -e "${BOLD}${GREEN}║${NC}  最终进度: $(get_test_progress)"
echo -e "${BOLD}${GREEN}║${NC}  日志目录: $LOG_DIR"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# 清理计数器文件
rm -f "$COUNTER_FILE"

# 显示最终报告
cat "$TEST_LOG" 2>/dev/null | tail -50
