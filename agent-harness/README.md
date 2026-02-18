# Long-Running Agent Harness

基于 Anthropic 的文章 [Effective harnesses for long-running agents](https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents) 实现的 Agent 工作流框架。

## 核心概念

### 问题背景

AI Agent 在处理跨多个 context window 的复杂任务时面临以下挑战：

1. **一次性尝试过多** - Agent 倾向于一次性完成所有任务，导致 context 耗尽时留下半成品
2. **过早宣布完成** - 后续 session 看到进展后可能错误地认为任务已完成
3. **缺乏测试验证** - Agent 可能标记功能完成但未经过适当测试

### 解决方案：双 Agent 架构

```
┌─────────────────────────────────────────────────────────────┐
│                    INITIALIZER AGENT                        │
│  - 创建 feature_list.json（功能需求列表）                    │
│  - 创建 init.sh（环境启动脚本）                              │
│  - 创建 claude-progress.txt（进度记录文件）                  │
│  - 初始化 git 仓库并提交初始文件                             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      CODING AGENT                            │
│  - 读取进度文件和 git 日志了解当前状态                       │
│  - 选择一个未完成的功能进行开发                              │
│  - 进行端到端测试验证                                        │
│  - 提交代码并更新进度文件                                    │
└─────────────────────────────────────────────────────────────┘
```

## 文件结构

```
agent-harness/
├── README.md                    # 本文档
├── init.sh                      # 环境初始化脚本模板
├── initializer_prompt.md        # Initializer Agent 提示词模板
├── coding_agent_prompt.md       # Coding Agent 提示词模板
├── feature_list.json            # 功能需求列表示例
└── claude-progress.txt          # 进度记录文件模板
```

## 使用方法

### 1. Initializer Agent（首次运行）

使用 `initializer_prompt.md` 作为提示词，Agent 将：
- 解析用户需求并生成详细的 feature_list.json
- 创建 init.sh 脚本用于启动开发环境
- 初始化进度记录文件
- 创建初始 git commit

### 2. Coding Agent（后续运行）

使用 `coding_agent_prompt.md` 作为提示词，每个 session 将：
- 运行 `pwd` 确认工作目录
- 读取 git 日志和进度文件了解状态
- 读取 feature_list.json 选择下一个功能
- 实现功能并进行端到端测试
- 提交代码并更新进度文件

## 最佳实践

### Feature List 规范

使用 JSON 格式存储功能列表，避免 Agent 意外修改：

```json
{
  "category": "functional",
  "description": "功能描述",
  "steps": [
    "步骤1",
    "步骤2"
  ],
  "passes": false
}
```

### 进度记录规范

每次 session 结束时记录：
- 完成了什么工作
- 遇到了什么问题
- 下一步需要做什么

### 测试要求

- 使用端到端测试验证功能
- 模拟真实用户操作
- 不要仅依赖单元测试或代码审查

## Agent 失败模式与解决方案

| 问题 | Initializer Agent 行为 | Coding Agent 行为 |
|------|----------------------|------------------|
| 过早宣布项目完成 | 创建详细的 feature_list.json | 每个 session 只处理一个功能 |
| 留下未完成的代码 | 初始化 git 和进度文件 | 读取进度和日志，运行基础测试 |
| 标记功能完成过早 | 创建 feature_list.json | 必须通过端到端测试才能标记为 passing |

## 参考资料

- [Effective harnesses for long-running agents](https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents)
- [Claude 4 Prompting Guide](https://docs.anthropic.com/en/docs/claude-code/prompting-guide)
