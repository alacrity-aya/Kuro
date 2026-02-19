# Kuro 低代码编辑器开发计划

**版本:** 2.0  
**日期:** 2026-02-18  
**状态:** 待开发

---

## 背景

当前 Kuro 前端支持通过 YAML 编辑器创建拓扑，但用户希望有一个更直观的低代码平台：
- 通过拖拽添加节点
- 在配置框中配置 image, role, labels 等
- 配置节点之间的链路网络仿真参数

---

## 后端能力分析

### NodeGroup CRD 支持

```yaml
spec:
  nodeGroups:
    - name: drones
      replicas: 5
      image: nicolaka/netshoot
      command: ["sleep", "infinity"]
      labels:
        role: drone
        team: red
      userProgram:
        source: |
          print("Hello from drone")
        mountPath: /app
        filename: main.py
```

### TrafficControl CRD 支持

```yaml
spec:
  priority: 100
  source:
    matchLabels:
      role: drone
  destination:
    matchLabels:
      role: ground-station
  policy:
    bandwidth: 10Mbps
    latency: 50ms
    jitter: 10ms
    packetLoss: 0.5%
```

### 后端 API

| 端点 | 方法 | 功能 |
|------|------|------|
| `/api/v1/topology` | GET | 获取拓扑节点列表 |
| `/api/v1/policy/link` | POST | 应用链路策略 |
| `/api/v1/policy/pod` | POST | 应用 Pod 策略 |
| `/api/v1/policy/node` | POST | 应用节点策略 |

---

## 功能开发计划

### Phase 1: 低代码编辑器基础 (高优先级)

#### LC-001: Node Palette - 节点工具栏

**目标:** 提供可拖拽的节点类型工具栏

**实现细节:**

1. 创建 `NodePalette` 组件 (`frontend/src/components/topology/NodePalette.tsx`)
   ```tsx
   interface NodePaletteProps {
     nodeTypes: NodeTypeDefinition[];
     onNodeDragStart: (type: string) => void;
   }
   ```

2. 创建 `DraggableNodeItem` 组件
   ```tsx
   interface DraggableNodeItemProps {
     type: string;
     icon: string;
     label: string;
     color: string;
   }
   ```

3. 预定义节点类型:
   ```typescript
   const NODE_TYPES = [
     { type: 'drone', icon: '🚁', label: 'Drone', color: '#3b82f6' },
     { type: 'ground-station', icon: '📡', label: 'Ground Station', color: '#10b981' },
     { type: 'gateway', icon: '🔀', label: 'Gateway', color: '#8b5cf6' },
     { type: 'server', icon: '🖥️', label: 'Server', color: '#6366f1' },
     { type: 'client', icon: '💻', label: 'Client', color: '#f59e0b' },
     { type: 'custom', icon: '📦', label: 'Custom', color: '#6b7280' },
   ];
   ```

4. 拖拽处理:
   ```typescript
   const onDragStart = (event: React.DragEvent, nodeType: string) => {
     event.dataTransfer.setData('application/reactflow', nodeType);
     event.dataTransfer.effectAllowed = 'move';
   };
   ```

**文件清单:**
- `frontend/src/components/topology/NodePalette.tsx`
- `frontend/src/components/topology/NodePalette.css`
- `frontend/src/components/topology/DraggableNodeItem.tsx`
- `frontend/src/components/topology/index.ts` (更新导出)

**测试步骤:**
1. 运行 `npm run test:run`
2. 导航到拓扑创建页面
3. 验证节点工具栏显示
4. 拖拽节点到画布
5. 验证节点成功添加

---

#### LC-002: Node Configuration Panel - 节点配置面板

**目标:** 点击节点后显示配置面板，支持配置所有 NodeGroup 字段

**实现细节:**

1. 创建 `NodeConfigPanel` 组件 (`frontend/src/components/topology/NodeConfigPanel.tsx`)
   ```tsx
   interface NodeConfigPanelProps {
     node: TopologyNode | null;
     onUpdate: (node: Partial<TopologyNode>) => void;
     onClose: () => void;
   }
   ```

2. 创建表单字段组件:
   - `ImageInput` - 镜像选择/输入
   - `LabelsEditor` - 标签键值对编辑器
   - `CommandInput` - 启动命令编辑器
   - `ReplicasInput` - 副本数输入
   - `UserProgramEditor` - 用户代码编辑器

3. 表单验证:
   ```typescript
   const validateNodeConfig = (config: NodeGroupConfig): ValidationResult => {
     const errors: string[] = [];
     if (!config.name) errors.push('Name is required');
     if (!config.image) errors.push('Image is required');
     if (config.replicas < 1) errors.push('Replicas must be at least 1');
     return { valid: errors.length === 0, errors };
   };
   ```

**文件清单:**
- `frontend/src/components/topology/NodeConfigPanel.tsx`
- `frontend/src/components/topology/NodeConfigPanel.css`
- `frontend/src/components/topology/ImageInput.tsx`
- `frontend/src/components/topology/LabelsEditor.tsx`
- `frontend/src/components/topology/CommandInput.tsx`
- `frontend/src/types/nodeConfig.ts`

**测试步骤:**
1. 运行 `npm run test:run`
2. 拖拽添加一个新节点
3. 点击节点打开配置面板
4. 修改各字段
5. 验证实时预览更新

---

#### LC-003: Link Drawing - 链路绘制功能

**目标:** 支持通过拖拽在节点之间创建链路连接

**实现细节:**

1. 扩展 `TopologyCanvas` 支持连接创建:
   ```tsx
   const onConnect = useCallback((connection: Connection) => {
     const newLink: TopologyLink = {
       id: `${connection.source}-${connection.target}`,
       sourceId: connection.source,
       targetId: connection.target,
       status: 'pending',
       policy: {
         bandwidth: '10Mbps',
         latency: '0ms',
         jitter: '0ms',
         packetLoss: '0%',
       },
     };
     setLinks((prev) => [...prev, newLink]);
   }, []);
   ```

2. 创建 `LinkCreationHandler`:
   ```typescript
   const handleLinkCreation = (sourceId: string, targetId: string) => {
     // 检查是否已存在相同连接
     // 创建默认策略
     // 添加到 links 状态
   };
   ```

3. 支持删除链路:
   ```typescript
   const handleKeyDown = useCallback((event: KeyboardEvent) => {
     if (event.key === 'Delete' || event.key === 'Backspace') {
       if (selectedLinkId) {
         setLinks((prev) => prev.filter((l) => l.id !== selectedLinkId));
       }
     }
   }, [selectedLinkId]);
   ```

**文件清单:**
- `frontend/src/components/topology/TopologyCanvas.tsx` (修改)
- `frontend/src/hooks/useLinkManagement.ts`
- `frontend/src/components/topology/TopologyCanvas.css` (更新)

**测试步骤:**
1. 运行 `npm run test:run`
2. 添加两个节点到画布
3. 拖拽创建链路
4. 验证链路显示
5. 删除链路

---

#### LC-004: Link Configuration Panel - 链路配置面板增强

**目标:** 增强链路配置面板，支持完整的网络仿真参数配置

**实现细节:**

1. 增强现有 `TrafficControlPanel`:
   ```tsx
   interface TrafficControlPanelProps {
     link: TopologyLink | null;
     onSave: (linkId: string, policy: TrafficPolicy) => void;
     onDelete: (linkId: string) => void;
     onClose: () => void;
   }
   ```

2. 添加更多参数:
   - Priority (优先级)
   - Queue Depth (队列深度)
   - Corruption Rate (误码率)

3. 参数格式化:
   ```typescript
   const formatBandwidth = (value: number): string => {
     if (value >= 1e9) return `${(value / 1e9).toFixed(1)}Gbps`;
     if (value >= 1e6) return `${(value / 1e6).toFixed(1)}Mbps`;
     if (value >= 1e3) return `${(value / 1e3).toFixed(1)}Kbps`;
     return `${value}bps`;
   };
   ```

**文件清单:**
- `frontend/src/components/TrafficControlPanel.tsx` (修改)
- `frontend/src/components/TrafficControlPanel.css` (更新)
- `frontend/src/utils/policyFormatters.ts`

**测试步骤:**
1. 运行 `npm run test:run`
2. 创建链路
3. 点击链路打开配置面板
4. 配置各参数
5. 保存配置

---

#### LC-005: Topology Editor Page - 拓扑编辑页面

**目标:** 创建专用的拓扑编辑页面，集成所有编辑组件

**实现细节:**

1. 页面布局:
   ```
   ┌─────────────────────────────────────────────────────────┐
   │ [Node Palette] │ [Canvas] │ [Config Panel] │
   │ │ │ │
   │ 🚁 Drone │ ┌───┐ ┌───┐ │ Name: drones │
   │ 📡 Ground │ │ A │───│ B │ │ Image: nginx │
   │ 🔀 Gateway │ └───┘ └───┘ │ Replicas: 3 │
   │ 🖥️ Server │ │ Labels: ... │
   │ 💻 Client │ │ │
   │ │ │ [Save] [Export] │
   └─────────────────────────────────────────────────────────┘
   ```

2. 创建 `TopologyEditor` 页面:
   ```tsx
   interface TopologyEditorProps {
     topologyId?: string; // 编辑现有拓扑时传入
     onSave: (topology: NetworkTopology) => void;
   }
   ```

3. 集成子组件:
   - NodePalette (左侧)
   - TopologyCanvas (中间)
   - NodeConfigPanel / TrafficControlPanel (右侧)

**文件清单:**
- `frontend/src/pages/TopologyEditor.tsx`
- `frontend/src/pages/TopologyEditor.css`
- `frontend/src/App.tsx` (添加路由)

**测试步骤:**
1. 运行 `npm run test:run`
2. 导航到 /topologies/new
3. 验证页面布局
4. 测试完整编辑流程
5. 截图验证

---

#### LC-006: Topology Save - 拓扑保存功能

**目标:** 将可视化编辑的拓扑保存为 CRD YAML 格式

**实现细节:**

1. 创建转换函数:
   ```typescript
   const editorStateToCRD = (
     nodes: EditorNode[],
     links: EditorLink[]
   ): { topology: NetworkTopology; trafficControls: TrafficControl[] } => {
     // 1. 聚合节点为 NodeGroups
     const nodeGroups = aggregateNodeGroups(nodes);
     
     // 2. 生成 NetworkTopology CRD
     const topology: NetworkTopology = {
       apiVersion: 'simulation.kuro.io/v1alpha1',
       kind: 'NetworkTopology',
       metadata: { name: '...', namespace: 'default' },
       spec: { nodeGroups },
     };
     
     // 3. 生成 TrafficControl CRDs
     const trafficControls = generateTrafficControls(links);
     
     return { topology, trafficControls };
   };
   ```

2. 创建 YAML 预览对话框:
   ```tsx
   interface YamlPreviewDialogProps {
     topology: NetworkTopology;
     trafficControls: TrafficControl[];
     onConfirm: () => void;
     onCancel: () => void;
   }
   ```

**文件清单:**
- `frontend/src/utils/topologyConverter.ts`
- `frontend/src/components/topology/YamlPreviewDialog.tsx`
- `frontend/src/stores/editorStore.ts`

**测试步骤:**
1. 运行 `npm run test:run`
2. 创建拓扑
3. 点击保存
4. 验证 YAML 格式
5. 确认保存

---

### Phase 2: 高级功能 (中优先级)

#### LC-007: Node Group Management - 节点组管理

**目标:** 支持将多个节点组织成节点组

**实现细节:**
- 创建 NodeGroupPanel 组件
- 支持多选节点
- 支持配置副本数
- 支持批量配置标签

---

#### LC-008: Topology Templates - 拓扑模板库

**目标:** 提供预定义的拓扑模板

**预定义模板:**
1. **Drone Swarm** - 1个地面站 + N个无人机
2. **IoT Network** - 网关 + 多个传感器节点
3. **Microservices** - API网关 + 多个服务
4. **Star Topology** - 中心节点 + 多个边缘节点
5. **Mesh Network** - 全连接网络

---

#### LC-009: Real-time Validation - 实时验证

**目标:** 实时验证拓扑配置

**验证规则:**
1. 节点名称唯一性
2. 必填字段检查
3. IP 地址格式验证
4. 镜像名称格式验证
5. 孤立节点警告

---

#### LC-010: Undo/Redo - 撤销/重做

**目标:** 支持编辑操作的撤销和重做

**实现细节:**
- 使用 Zustand 的 temporal 中间件
- 支持快捷键 Ctrl+Z / Ctrl+Y
- 支持最多 50 步历史记录

---

## 开发顺序

推荐按以下顺序开发：

```
Week 1: LC-001 (Node Palette) → LC-003 (Link Drawing)
Week 2: LC-002 (Node Config Panel) → LC-004 (Link Config Panel)
Week 3: LC-005 (Topology Editor Page) → LC-006 (Topology Save)
Week 4: LC-007 (Node Groups) → LC-008 (Templates)
Week 5: LC-009 (Validation) → LC-010 (Undo/Redo)
```

---

## 运行开发 Agent

```bash
# 启动开发循环
./scripts/run-agent-loop.sh

# 或使用快速脚本
./scripts/kuro-test-quick.sh
```

---

## 注意事项

1. **每个 Feature 的最后一步必须是测试**
   - 代码测试: `npm run test:run`
   - 浏览器测试: 使用 MCP 浏览器工具
   - 截图保存: 至少 2 张截图

2. **遵循现有代码风格**
   - 使用 TypeScript
   - 使用 Zustand 进行状态管理
   - 使用 React Flow 进行拓扑可视化
   - 组件放在 `frontend/src/components/` 目录

3. **后端 API 集成**
   - 当前使用 Mock API
   - 保持 API 接口一致
   - 未来可无缝切换到真实后端

---

## 更新日志

- 2026-02-18: 创建低代码编辑器开发计划，添加 10 个新功能
