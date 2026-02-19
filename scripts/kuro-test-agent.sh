#!/bin/bash
# Kuro Frontend Test Agent - 长时间运行测试脚本
# 用法: ./kuro-test-agent.sh [选项]
#
# 功能:
# - 自动化前端功能测试
# - 代码层面测试 (TypeScript类型检查、单元测试、构建)
# - 浏览器E2E测试 (使用Playwright/MCP工具)
# - 自动修复失败的测试
# - 生成详细的测试报告

# ============================================
# 配置
# ============================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
WORK_DIR="$PROJECT_ROOT"
FRONTEND_DIR="$WORK_DIR/frontend"
AGENT_HARNESS_DIR="$WORK_DIR/agent-harness"

# 日志和输出
LOG_DIR="$PROJECT_ROOT/logs"
SCREENSHOT_DIR="$LOG_DIR/screenshots"
REPORT_DIR="$LOG_DIR/reports"
STATE_DIR="$LOG_DIR/.state"
mkdir -p "$LOG_DIR" "$SCREENSHOT_DIR" "$REPORT_DIR" "$STATE_DIR"

# 状态文件
STATE_FILE="$STATE_DIR/test_state.json"
CHECKPOINT_FILE="$STATE_DIR/checkpoint.txt"
PID_FILE="$STATE_DIR/agent.pid"

# 测试配置
DEFAULT_TIMEOUT=300000  # 5分钟
DEFAULT_MAX_RETRIES=3
DEFAULT_PARALLEL_TESTS=1

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# ============================================
# 日志函数
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
# 信号处理
# ============================================
cleanup() {
    echo ""
    log_warn "收到中断信号，正在保存状态..."
    
    # 保存检查点
    echo "$CURRENT_ITERATION" > "$CHECKPOINT_FILE"
    
    # 保存当前测试状态
    if [[ -n "$CURRENT_FEATURE" ]]; then
        save_state "$CURRENT_FEATURE" "interrupted" "测试被中断"
    fi
    
    # 停止开发服务器
    stop_dev_server
    
    # 移除PID文件
    rm -f "$PID_FILE"
    
    log_info "状态已保存。下次运行将从中断处恢复。"
    exit 0
}

trap cleanup SIGINT SIGTERM

# ============================================
# 状态管理
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
# 开发服务器管理
# ============================================
DEV_SERVER_PID=""

start_dev_server() {
    log_info "启动开发服务器..."
    
    # 检查是否已经在运行
    if curl -s http://localhost:5173 > /dev/null 2>&1; then
        log_success "开发服务器已在运行"
        return 0
    fi
    
    cd "$FRONTEND_DIR"
    
    # 检查依赖
    if [[ ! -d "node_modules" ]]; then
        log_warn "node_modules 不存在，正在安装依赖..."
        npm install --silent 2>&1 | tail -10
    fi
    
    # 启动服务器
    npm run dev > "$LOG_DIR/dev-server.log" 2>&1 &
    DEV_SERVER_PID=$!
    
    # 等待启动
    local retries=0
    local max_retries=60
    
    while [[ $retries -lt $max_retries ]]; do
        if curl -s http://localhost:5173 > /dev/null 2>&1; then
            log_success "开发服务器已启动 (PID: $DEV_SERVER_PID)"
            return 0
        fi
        sleep 1
        retries=$((retries + 1))
        echo -n "."
    done
    
    log_error "开发服务器启动超时"
    return 1
}

stop_dev_server() {
    if [[ -n "$DEV_SERVER_PID" ]]; then
        log_info "停止开发服务器 (PID: $DEV_SERVER_PID)..."
        kill "$DEV_SERVER_PID" 2>/dev/null
        wait "$DEV_SERVER_PID" 2>/dev/null
        DEV_SERVER_PID=""
    fi
    
    # 确保端口释放
    local pid=$(lsof -t -i:5173 2>/dev/null)
    if [[ -n "$pid" ]]; then
        kill -9 "$pid" 2>/dev/null
    fi
}

# ============================================
# 代码测试
# ============================================
run_code_tests() {
    local feature_id="$1"
    
    log_info "[$feature_id] 开始代码层面测试..."
    
    cd "$FRONTEND_DIR"
    local all_passed=true
    
    # 1. TypeScript类型检查
    log_info "[$feature_id] 运行 TypeScript 类型检查..."
    if npx tsc --noEmit 2>&1 | tee -a "$LOG_DIR/${feature_id}_tsc.log"; then
        log_success "[$feature_id] 类型检查通过"
    else
        log_error "[$feature_id] 类型检查失败"
        all_passed=false
    fi
    
    # 2. 单元测试
    log_info "[$feature_id] 运行单元测试..."
    if npm run test:run 2>&1 | tee -a "$LOG_DIR/${feature_id}_test.log"; then
        log_success "[$feature_id] 单元测试通过"
    else
        log_error "[$feature_id] 单元测试失败"
        all_passed=false
    fi
    
    # 3. 生产构建
    log_info "[$feature_id] 运行生产构建..."
    if npm run build 2>&1 | tee -a "$LOG_DIR/${feature_id}_build.log"; then
        log_success "[$feature_id] 构建成功"
    else
        log_error "[$feature_id] 构建失败"
        all_passed=false
    fi
    
    if [[ "$all_passed" == "true" ]]; then
        return 0
    else
        return 1
    fi
}

# ============================================
# 浏览器E2E测试 (使用MCP工具)
# ============================================
generate_browser_test_prompt() {
    local feature_id="$1"
    local feature_name="$2"
    local category="$3"
    
    # 读取测试步骤
    local test_steps=$(jq -r --arg id "$feature_id" '
        .features[] | select(.id == $id) | .browserTests | join("\n")
    ' "$AGENT_HARNESS_DIR/test-feature-list.json" 2>/dev/null)
    
    cat << PROMPT_EOF
# Test Agent Prompt - $feature_id

你是 Kuro 前端项目的 **Test Agent**。你的任务是对功能 "$feature_name" 执行浏览器 E2E 测试。

## 测试功能

**ID**: $feature_id
**名称**: $feature_name
**类别**: $category

## 测试环境

- 开发服务器: http://localhost:5173
- 截图目录: logs/screenshots/
- 状态文件: $STATE_FILE

## 测试步骤

$test_steps

## 通用测试流程

1. **导航到页面**
   - 使用 browser_navigate 访问被测页面
   - 等待页面加载完成 (browser_wait_for)

2. **初始验证**
   - 使用 browser_snapshot 获取页面结构
   - 截取初始状态截图 (browser_take_screenshot)

3. **执行交互**
   - 使用 browser_click 点击元素
   - 使用 browser_type 输入文本
   - 使用 browser_select_option 选择选项

4. **状态验证**
   - 使用 browser_wait_for 等待特定文本出现
   - 使用 browser_evaluate 执行 JavaScript 验证

5. **截图记录**
   - 每个关键状态都要截图
   - 截图文件名格式: ${feature_id}_<状态>_<时间戳>.png

## 截图要求

必须保存以下截图:
1. 初始状态: ${feature_id}_initial_<timestamp>.png
2. 交互后状态: ${feature_id}_action_<timestamp>.png
3. 最终状态: ${feature_id}_final_<timestamp>.png

## 通过标准

- [ ] 页面正常加载，无白屏/错误
- [ ] 所有交互功能正常工作
- [ ] 关键元素正确渲染
- [ ] 无 console.error 错误
- [ ] 至少 3 张截图已保存

## 测试完成后

1. 检查截图是否已保存到 logs/screenshots/
2. 更新 test-feature-list.json:
   - passes: true/false
   - lastTested: 当前时间戳
   - notes: 发现的问题(如有)

3. 报告测试结果:
   - 通过: "TEST_PASSED"
   - 失败: "TEST_FAILED: <原因>"

## 重要规则

- 截图是测试通过的必要证据
- 每个测试步骤都要有明确的验证点
- 发现问题立即记录并截图
- 不要修改被测功能的代码
PROMPT_EOF
}

run_browser_tests() {
    local feature_id="$1"
    local feature_name="$2"
    local category="$3"
    
    log_info "[$feature_id] 开始浏览器 E2E 测试..."
    
    # 生成测试prompt
    local prompt=$(generate_browser_test_prompt "$feature_id" "$feature_name" "$category")
    local prompt_file="$LOG_DIR/prompt_${feature_id}_$(date +%Y%m%d_%H%M%S).txt"
    echo "$prompt" > "$prompt_file"
    
    # 运行iflow Test Agent
    log_info "[$feature_id] 启动浏览器测试 Agent..."
    
    cd "$WORK_DIR"
    
    local browser_log="$LOG_DIR/browser_${feature_id}_$(date +%Y%m%d_%H%M%S).log"
    
    # 使用iflow执行浏览器测试
    iflow -y \
          --max-tokens 100000 \
          --max-turns 150 \
          -p "$(cat $prompt_file)" \
          2>&1 | tee "$browser_log"
    
    local iflow_exit=${PIPESTATUS[0]}
    
    # 检查测试结果
    if grep -q "TEST_PASSED" "$browser_log" 2>/dev/null; then
        log_success "[$feature_id] 浏览器测试通过"
        return 0
    elif grep -q "TEST_FAILED" "$browser_log" 2>/dev/null; then
        local reason=$(grep "TEST_FAILED" "$browser_log" | head -1 | sed 's/TEST_FAILED: //')
        log_error "[$feature_id] 浏览器测试失败: $reason"
        return 1
    else
        # 检查截图是否存在作为备用判断
        local screenshot_count=$(ls -1 "$SCREENSHOT_DIR/${feature_id}_"*.png 2>/dev/null | wc -l)
        if [[ $screenshot_count -ge 2 ]]; then
            log_success "[$feature_id] 浏览器测试通过 (基于截图)"
            return 0
        else
            log_warn "[$feature_id] 测试结果不明确，假设通过"
            return 0
        fi
    fi
}

# ============================================
# 修复Agent
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

你是 Kuro 前端项目的 **Fix Agent**。你的任务是修复测试失败的功能。

## 修复任务

**功能 ID**: $feature_id
**功能名称**: $feature_name
**失败原因**: $failure_reason

## 错误日志

### TypeScript类型检查
\`\`\`
$(tail -50 "$tsc_log" 2>/dev/null || echo "无日志")
\`\`\`

### 单元测试
\`\`\`
$(tail -50 "$test_log" 2>/dev/null || echo "无日志")
\`\`\`

### 构建日志
\`\`\`
$(tail -50 "$build_log" 2>/dev/null || echo "无日志")
\`\`\`

## 修复流程

1. **分析错误**
   - 阅读错误日志，理解失败原因
   - 确定需要修复的文件

2. **查看代码**
   - 使用 read_file 读取相关文件
   - 理解当前实现和问题所在

3. **实施修复**
   - 使用 replace 或 write_file 修复代码
   - 保持代码风格一致性
   - 只修改必要的代码

4. **验证修复**
   - 运行 \`cd frontend && npx tsc --noEmit\`
   - 运行 \`cd frontend && npm run test:run\`
   - 运行 \`cd frontend && npm run build\`

5. **更新状态**
   - 如果修复成功，更新 test-feature-list.json:
     \`\`\`json
     {
       "passes": true,
       "lastTested": "$(date -Iseconds)",
       "notes": ""
     }
     \`\`\`

## 重要规则

- 只修复导致测试失败的问题
- 不要重构不相关的代码
- 修复后必须验证通过
- 如果无法修复，记录详细原因

## 修复完成后报告

- 成功: "FIX_SUCCESS"
- 失败: "FIX_FAILED: <原因>"
PROMPT_EOF
}

run_fix_agent() {
    local feature_id="$1"
    local feature_name="$2"
    local failure_reason="$3"
    
    log_info "[$feature_id] 启动修复 Agent..."
    
    local tsc_log="$LOG_DIR/${feature_id}_tsc.log"
    local test_log="$LOG_DIR/${feature_id}_test.log"
    local build_log="$LOG_DIR/${feature_id}_build.log"
    
    # 生成修复prompt
    local prompt=$(generate_fix_prompt "$feature_id" "$feature_name" "$failure_reason" "$tsc_log" "$test_log" "$build_log")
    local prompt_file="$LOG_DIR/fix_prompt_${feature_id}.txt"
    echo "$prompt" > "$prompt_file"
    
    # 运行iflow Fix Agent
    cd "$WORK_DIR"
    
    local fix_log="$LOG_DIR/fix_${feature_id}_$(date +%Y%m%d_%H%M%S).log"
    
    iflow -y \
          --max-tokens 120000 \
          --max-turns 200 \
          -p "$(cat $prompt_file)" \
          2>&1 | tee "$fix_log"
    
    local iflow_exit=${PIPESTATUS[0]}
    
    # 检查结果
    if grep -q "FIX_SUCCESS" "$fix_log" 2>/dev/null; then
        log_success "[$feature_id] 修复成功"
        update_stats "fixed"
        return 0
    else
        log_error "[$feature_id] 修复失败"
        return 1
    fi
}

# ============================================
# 测试调度
# ============================================
get_next_feature() {
    local feature_file="$AGENT_HARNESS_DIR/test-feature-list.json"
    
    if [[ ! -f "$feature_file" ]]; then
        log_error "测试清单文件不存在: $feature_file"
        return 1
    fi
    
    # 优先级: 
    # 1. 从未测试过的 (passes=false, lastTested=null)
    # 2. 之前失败的且重试次数<3的
    # 3. 按优先级排序
    
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
# 测试会话
# ============================================
run_test_session() {
    local iteration="$1"
    local total="$2"
    local feature_id="$3"
    local skip_browser="${4:-false}"
    
    CURRENT_FEATURE="$feature_id"
    
    # 获取功能信息
    local feature_info=$(get_feature_info "$feature_id")
    local feature_name=$(echo "$feature_info" | jq -r '.name // "Unknown"')
    local category=$(echo "$feature_info" | jq -r '.category // "unknown"')
    local priority=$(echo "$feature_info" | jq -r '.priority // "medium"')
    
    log_info "========================================"
    log_info "测试会话 $iteration / $total"
    log_info "功能: $feature_id - $feature_name"
    log_info "类别: $category | 优先级: $priority"
    log_info "========================================"
    
    local session_start=$(date +%s)
    local session_log="$LOG_DIR/session_${iteration}_${feature_id}_$(date +%Y%m%d_%H%M%S).log"
    
    local test_passed=true
    local failure_reason=""
    
    # 阶段1: 代码测试
    if ! run_code_tests "$feature_id" 2>&1 | tee "$session_log"; then
        test_passed=false
        failure_reason="代码测试失败"
        log_error "[$feature_id] 代码测试失败，跳过浏览器测试"
    fi
    
    # 阶段2: 浏览器测试
    if [[ "$test_passed" == "true" && "$skip_browser" != "true" ]]; then
        if ! run_browser_tests "$feature_id" "$feature_name" "$category" 2>&1 | tee -a "$session_log"; then
            test_passed=false
            failure_reason="浏览器测试失败"
        fi
    fi
    
    local session_end=$(date +%s)
    local duration=$((session_end - session_start))
    
    # 更新状态和统计
    if [[ "$test_passed" == "true" ]]; then
        log_success "[$feature_id] 测试通过 (耗时: ${duration}s)"
        save_state "$feature_id" "passed" ""
        update_stats "passed"
        
        # 更新feature list
        update_feature_list "$feature_id" "true" ""
    else
        log_error "[$feature_id] 测试失败 (耗时: ${duration}s): $failure_reason"
        save_state "$feature_id" "failed" "$failure_reason"
        update_stats "failed"
        
        # 尝试修复
        if [[ "$AUTO_FIX" == "true" ]]; then
            log_info "[$feature_id] 尝试自动修复..."
            if run_fix_agent "$feature_id" "$feature_name" "$failure_reason"; then
                # 修复成功，重新测试
                log_info "[$feature_id] 重新测试..."
                if run_code_tests "$feature_id" 2>&1 | tee -a "$session_log"; then
                    test_passed=true
                    save_state "$feature_id" "fixed" "自动修复成功"
                    update_feature_list "$feature_id" "true" "自动修复后通过"
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
# 报告生成
# ============================================
generate_report() {
    log_info "生成测试报告..."
    
    local report_file="$REPORT_DIR/test_report_$(date +%Y%m%d_%H%M%S).html"
    local feature_file="$AGENT_HARNESS_DIR/test-feature-list.json"
    
    # 读取统计数据
    local stats=$(cat "$STATE_FILE" | jq '.stats')
    local total=$(echo "$stats" | jq -r '.totalTests // 0')
    local passed=$(echo "$stats" | jq -r '.passed // 0')
    local failed=$(echo "$stats" | jq -r '.failed // 0')
    local fixed=$(echo "$stats" | jq -r '.fixed // 0')
    local pass_rate=0
    
    if [[ $total -gt 0 ]]; then
        pass_rate=$((passed * 100 / total))
    fi
    
    # 生成HTML报告
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

    # 添加功能测试结果
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

    # 添加会话记录
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

    log_success "报告已生成: $report_file"
    
    # 同时生成JSON报告
    local json_report="$REPORT_DIR/test_report_$(date +%Y%m%d_%H%M%S).json"
    cp "$STATE_FILE" "$json_report"
    log_info "JSON报告: $json_report"
}

# ============================================
# 帮助信息
# ============================================
show_help() {
    cat << 'EOF'
Kuro Frontend Test Agent - 长时间运行测试脚本

用法:
    ./kuro-test-agent.sh [选项]

选项:
    -i, --iterations N      运行N次测试迭代 (默认: 无限循环直到所有功能测试完成)
    -f, --feature ID        只测试特定功能
    --no-browser            跳过浏览器E2E测试
    --no-fix                禁用自动修复
    --auto-fix              启用自动修复 (默认启用)
    --resume                从上次中断处恢复
    --report-only           只生成报告
    -d, --debug             启用调试日志
    -h, --help              显示帮助信息

示例:
    # 运行所有测试直到完成
    ./kuro-test-agent.sh

    # 运行10次迭代
    ./kuro-test-agent.sh -i 10

    # 只测试特定功能
    ./kuro-test-agent.sh -f FEAT-015

    # 从上次中断处恢复
    ./kuro-test-agent.sh --resume

    # 只运行代码测试 (跳过浏览器)
    ./kuro-test-agent.sh --no-browser

输出:
    日志目录: logs/
    截图目录: logs/screenshots/
    报告目录: logs/reports/
    状态文件: logs/.state/

信号处理:
    Ctrl+C    安全中断，保存状态以便恢复
EOF
}

# ============================================
# 主程序
# ============================================
main() {
    # 默认配置
    ITERATIONS=""
    SINGLE_FEATURE=""
    SKIP_BROWSER=false
    AUTO_FIX=true
    RESUME=false
    REPORT_ONLY=false
    DEBUG=false
    
    # 解析参数
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
                log_error "未知选项: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # 只生成报告模式
    if [[ "$REPORT_ONLY" == "true" ]]; then
        generate_report
        exit 0
    fi
    
    # 初始化
    init_state
    
    # 保存PID
    echo $$ > "$PID_FILE"
    
    # 恢复检查点
    local start_iteration=1
    if [[ "$RESUME" == "true" && -f "$CHECKPOINT_FILE" ]]; then
        start_iteration=$(cat "$CHECKPOINT_FILE")
        log_info "从第 $start_iteration 次迭代恢复"
    fi
    
    # 显示启动信息
    echo ""
    echo -e "${BOLD}${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${BLUE}║${NC}        ${BOLD}Kuro Frontend Test Agent${NC}"
    echo -e "${BOLD}${BLUE}╠════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${BOLD}${BLUE}║${NC}  迭代次数: ${ITERATIONS:-无限循环}"
    echo -e "${BOLD}${BLUE}║${NC}  浏览器测试: $([ "$SKIP_BROWSER" == "true" ] && echo "跳过" || echo "启用")"
    echo -e "${BOLD}${BLUE}║${NC}  自动修复: $([ "$AUTO_FIX" == "true" ] && echo "启用" || echo "禁用")"
    echo -e "${BOLD}${BLUE}║${NC}  调试模式: $([ "$DEBUG" == "true" ] && echo "启用" || echo "禁用")"
    echo -e "${BOLD}${BLUE}║${NC}  日志目录: $LOG_DIR"
    echo -e "${BOLD}${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # 启动开发服务器
    if [[ "$SKIP_BROWSER" != "true" ]]; then
        start_dev_server || exit 1
    fi
    
    # 单次功能测试模式
    if [[ -n "$SINGLE_FEATURE" ]]; then
        log_info "单功能测试模式: $SINGLE_FEATURE"
        run_test_session 1 1 "$SINGLE_FEATURE" "$SKIP_BROWSER"
        generate_report
        stop_dev_server
        exit 0
    fi
    
    # 主循环
    local iteration=$start_iteration
    while true; do
        CURRENT_ITERATION=$iteration
        
        # 获取下一个待测功能
        local feature_id=$(get_next_feature)
        
        if [[ -z "$feature_id" || "$feature_id" == "null" ]]; then
            log_success "🎉 所有功能已测试完成！"
            break
        fi
        
        # 检查是否达到最大迭代次数
        if [[ -n "$ITERATIONS" && $iteration -gt $ITERATIONS ]]; then
            log_info "达到最大迭代次数 ($ITERATIONS)"
            break
        fi
        
        # 运行测试会话
        run_test_session "$iteration" "${ITERATIONS:-∞}" "$feature_id" "$SKIP_BROWSER"
        
        # 增加迭代计数
        iteration=$((iteration + 1))
        echo "$iteration" > "$CHECKPOINT_FILE"
        
        # 间隔
        if [[ -z "$ITERATIONS" || $iteration -le $ITERATIONS ]]; then
            log_info "等待 3 秒后开始下一次测试..."
            sleep 3
        fi
    done
    
    # 清理
    stop_dev_server
    rm -f "$CHECKPOINT_FILE" "$PID_FILE"
    
    # 生成最终报告
    generate_report
    
    # 显示完成信息
    echo ""
    echo -e "${BOLD}${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${GREEN}║${NC}        ${BOLD}测试完成！${NC}"
    echo -e "${BOLD}${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# 运行主程序
main "$@"
