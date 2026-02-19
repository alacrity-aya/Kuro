# Kuro Frontend Test Agent 使用指南

## 简介

Kuro Test Agent 是一个长时间运行的前端自动化测试框架，支持代码层面测试和浏览器E2E测试。

## 快速开始

### 1. 使用交互式菜单（推荐新手）

```bash
./scripts/kuro-test-quick.sh
```

选择菜单选项即可开始测试。

### 2. 直接运行完整测试

```bash
# 运行所有测试直到完成（包含自动修复）
./scripts/kuro-test-agent.sh

# 只运行代码测试（快速）
./scripts/kuro-test-agent.sh --no-browser

# 从上次中断处恢复
./scripts/kuro-test-agent.sh --resume
```

### 3. 监控测试进度

在另一个终端运行：

```bash
# 查看当前状态
./scripts/kuro-test-monitor.sh status

# 持续监控
./scripts/kuro-test-monitor.sh watch

# 查看最近日志
./scripts/kuro-test-monitor.sh logs 100
```

## 常用命令速查

| 命令 | 说明 |
|------|------|
| `./kuro-test-quick.sh` | 交互式菜单 |
| `./kuro-test-quick.sh full` | 完整测试 |
| `./kuro-test-quick.sh code` | 代码测试 |
| `./kuro-test-quick.sh single FEAT-015` | 单个功能 |
| `./kuro-test-agent.sh -i 10` | 运行10次迭代 |
| `./kuro-test-agent.sh --no-browser` | 跳过浏览器测试 |
| `./kuro-test-agent.sh --no-fix` | 禁用自动修复 |

## 测试流程

```
1. 启动开发服务器
        ↓
2. 选择待测功能（按优先级）
        ↓
3. 代码层面测试
   ├── TypeScript类型检查
   ├── 单元测试 (vitest)
   └── 生产构建 (vite build)
        ↓
4. 浏览器E2E测试 (如通过代码测试)
   ├── 导航到页面
   ├── 执行交互
   ├── 验证结果
   └── 截图记录
        ↓
5. 更新状态
   ├── 更新test-feature-list.json
   ├── 保存测试状态
   └── 生成报告
        ↓
6. 下一个功能或完成
```

## 功能测试清单

当前有 **10个功能** 待测试：

### 高优先级
- FEAT-014: Production Build Verification
- FEAT-015: Node Local View
- FEAT-016: Topology Creation with YAML Editor
- DASH-001: Dashboard Statistics Display
- CANVAS-001: Topology Canvas Visualization

### 中优先级
- FEAT-017: TSN Mode
- FEAT-018: Topology Export/Import
- LIST-001: Topology List Filtering
- LAYOUT-001: Sidebar Navigation
- TC-001: Traffic Control Panel

## 输出文件

测试过程中会生成以下文件：

```
logs/
├── agent.log                    # 主日志
├── dev-server.log              # 开发服务器日志
├── .state/
│   ├── test_state.json         # 测试状态
│   ├── checkpoint.txt          # 检查点
│   └── agent.pid               # 进程ID
├── screenshots/                # 浏览器测试截图
│   └── FEAT-XXX_*.png
├── reports/                    # 测试报告
│   ├── test_report_*.html      # HTML报告
│   └── test_report_*.json      # JSON报告
└── session_*_*.log             # 会话日志
```

## 测试通过标准

### 代码层面
- ✅ TypeScript类型检查通过 (`tsc --noEmit`)
- ✅ 单元测试全部通过 (`npm run test:run`)
- ✅ 生产构建成功 (`npm run build`)

### 浏览器层面
- ✅ 页面正常加载，无白屏/错误
- ✅ 关键交互功能正常工作
- ✅ 至少3张截图已保存
- ✅ 无console.error错误

## 中断与恢复

测试过程中可以随时按 `Ctrl+C` 中断：

```bash
# 中断后会自动保存状态
^C
[INFO] 状态已保存。下次运行将从中断处恢复。

# 从上次中断处恢复
./scripts/kuro-test-agent.sh --resume
```

## 故障排除

### 端口被占用

```bash
# 检查端口
lsof -i :5173

# 手动停止开发服务器
pkill -f "vite"
```

### 测试agent卡住

```bash
# 检查agent状态
./scripts/kuro-test-monitor.sh status

# 强制停止
rm -f logs/.state/agent.pid
pkill -f "kuro-test-agent"
```

### 清理重新测试

```bash
./scripts/kuro-test-quick.sh clean
# 或
rm -rf logs/*
```

## 查看报告

测试完成后可以查看生成的HTML报告：

```bash
# 列出所有报告
ls -la logs/reports/

# 查看最新报告
firefox logs/reports/test_report_*.html
# 或
google-chrome logs/reports/test_report_*.html
```

## 添加新功能测试

1. 编辑 `agent-harness/test-feature-list.json`
2. 添加新的feature对象：

```json
{
  "id": "FEAT-019",
  "category": "functional",
  "priority": "high",
  "name": "New Feature Name",
  "description": "Feature description",
  "codeTests": ["测试步骤1", "测试步骤2"],
  "browserTests": ["浏览器测试步骤1"],
  "passes": false,
  "lastTested": null,
  "notes": ""
}
```

3. 运行测试：

```bash
./scripts/kuro-test-agent.sh -f FEAT-019
```

## 架构说明

测试Agent包含三个主要脚本：

1. **kuro-test-agent.sh** - 核心引擎
   - 智能调度算法
   - 代码测试执行
   - 浏览器E2E测试协调
   - 自动修复触发
   - 报告生成

2. **kuro-test-monitor.sh** - 监控工具
   - 实时状态显示
   - 日志查看
   - 快速报告生成

3. **kuro-test-quick.sh** - 快速启动
   - 交互式菜单
   - 常用命令快捷方式

## 注意事项

1. **截图证据**: 浏览器测试必须保存至少3张截图
2. **独立性**: 每个功能测试应该独立运行
3. **失败处理**: 代码测试失败会跳过浏览器测试
4. **资源管理**: 脚本自动管理开发服务器启停
5. **状态持久化**: 使用 `--resume` 可从中断处恢复

## 获取帮助

```bash
# 查看帮助
./scripts/kuro-test-agent.sh --help
./scripts/kuro-test-monitor.sh help
./scripts/kuro-test-quick.sh help

# 查看README
cat agent-harness/README.md
```

## 示例会话

```bash
# 终端1: 启动测试
$ ./scripts/kuro-test-quick.sh
选择 [0-7]: 1
[INFO] 启动完整测试...
...

# 终端2: 监控进度
$ ./scripts/kuro-test-monitor.sh watch
刷新显示当前状态...

# 测试完成后查看报告
$ firefox logs/reports/test_report_*.html
```