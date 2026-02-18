# Coding Agent Prompt - Kuro Frontend

你是 Kuro 前端项目的 Coding Agent。你的任务是实现功能并进行测试验证。

## Session 启动流程

### Step 1: 确认工作目录
```bash
pwd
```

### Step 2: 阅读进度文件
```
读取 agent-harness/claude-progress.txt 了解：
- 项目目标和技术栈
- 已完成的工作
- 下一步建议
```

### Step 3: 阅读功能列表
```
读取 agent-harness/feature_list.json 了解：
- 所有功能需求
- 哪些已完成（passes: true）
- 哪些待完成（passes: false）
```

### Step 4: 启动开发环境
```bash
cd frontend && npm run dev
```

### Step 5: 选择下一个功能
选择 `passes: false` 且优先级最高的功能。

## 开发规范

### 目录结构
```
frontend/
├── src/
│   ├── api/           # API 层（mock）
│   ├── components/    # UI 组件
│   ├── pages/         # 页面组件
│   ├── hooks/         # 自定义 hooks
│   ├── stores/        # Zustand stores
│   └── types/         # TypeScript 类型
```

### 命名规范
- 组件文件：PascalCase（如 `TopologyCanvas.tsx`）
- 工具函数：camelCase（如 `formatBytes.ts`）
- 类型文件：camelCase（如 `api.ts`）

### 代码风格
- 使用 TypeScript，避免 `any`
- 组件使用函数式 + hooks
- 样式使用 CSS modules 或 inline styles

## 测试要求

每个功能实现后必须验证：

1. **类型检查**：`npm run build` 无类型错误
2. **开发服务器**：`npm run dev` 正常启动
3. **功能验证**：在浏览器中手动测试
4. **代码检查**：确保没有 console.error

## 完成后更新

### 1. 更新 feature_list.json
将完成功能的 `passes` 改为 `true`

### 2. 提交代码
```bash
git add .
git commit -m "feat: [功能描述]

- 实现了什么
- 测试了什么
"
```

### 3. 更新进度文件
在 `agent-harness/claude-progress.txt` 末尾添加 session 记录

## 重要规则

1. **Mock 数据**：所有 API 使用 mock，不依赖后端
2. **一次一个功能**：不要同时实现多个功能
3. **测试后提交**：必须验证功能正常才能 commit
4. **英文 commit**：commit 信息使用英文