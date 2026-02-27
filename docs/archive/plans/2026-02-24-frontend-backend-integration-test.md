# Frontend-Backend Integration Test Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 验证前端操作能正确反映到后端 Kubernetes CRD，测试前后端连通性

**Architecture:** 
- 前端 React + Vite 通过代理连接后端 API (:8080)
- 后端 Go Controller 提供 REST API 操作 K8s CRD
- 测试覆盖 NetworkTopology 和 TrafficControl 的 CRUD 操作

**Tech Stack:** React, Vite, Go, Kubernetes, Kind, gorilla/mux

**Test Scope:** 从 commit 4371ebbbd56bd46d088e1e728ac420b1bb68cf0b 开始的代码变更

**Known Bugs to Verify:**
1. 创建 topology 后列表不显示
2. 删除 topology 功能需要验证

---

## Prerequisites

- Kubernetes cluster (Kind: kuro-dev)
- Backend API running on port 8080
- Frontend dev server on port 5173

---

### Task 1: 启动后端环境

**Files:**
- Script: `scripts/setup_env.sh`

**Step 1: 检查现有 Kind 集群状态**

Run: `kind get clusters`
Expected: `kuro-dev` 存在，或者为空

**Step 2: 运行环境设置脚本**

Run: `./scripts/setup_env.sh`
Expected: 
- 集群创建/连接成功
- CRD 应用成功
- Controller 和 Agent Pod 运行中
- Port-forward 到 8080 端口

**Step 3: 验证后端 API 可访问**

Run: `curl -s http://localhost:8080/api/v1/namespaces/default/networktopologies | jq .`
Expected: 返回 JSON 格式的 topology 列表（可能为空）

**Step 4: 验证 K8s 资源状态**

Run: `kubectl get pods -n kuro-system`
Expected: kuro-controller 和 kuro-agent pods Running

---

### Task 2: 启动前端开发服务器

**Files:**
- Config: `frontend/vite.config.ts`
- Env: `frontend/.env.local`

**Step 1: 进入前端目录并安装依赖**

Run: `cd frontend && npm install`
Expected: 依赖安装成功

**Step 2: 启动开发服务器**

Run: `npm run dev`
Expected: 服务器启动在 http://localhost:5173

**Step 3: 验证前端代理配置**

在浏览器访问 http://localhost:5173
Expected: 页面正常加载，控制台无代理错误

---

### Task 3: 测试创建 Topology 功能 (Bug #1 验证)

**Files:**
- Frontend: `frontend/src/pages/TopologyCreate.tsx`
- Frontend: `frontend/src/api/client.ts`
- Backend: `internal/controller/api/server.go`

**Step 1: 准备测试数据**

使用默认 YAML:
```yaml
apiVersion: simulation.kuro.io/v1alpha1
kind: NetworkTopology
metadata:
  name: test-topology-1
  namespace: default
spec:
  nodeGroups:
    - name: leader
      replicas: 1
      image: nicolaka/netshoot
      labels:
        role: leader
    - name: follower
      replicas: 2
      image: nicolaka/netshoot
      labels:
        role: follower
```

**Step 2: 通过前端创建 Topology**

操作:
1. 访问 http://localhost:5173/topologies/create
2. 确认 YAML 编辑器内容
3. 点击 "Create Topology" 按钮
4. 观察响应

Expected: 
- 前端显示创建成功
- 页面跳转回 /topologies 列表页

**Step 3: 直接通过 API 验证 CRD 创建**

Run: `curl -s http://localhost:8080/api/v1/namespaces/default/networktopologies/test-topology-1 | jq .`
Expected: 返回创建的 topology 对象

**Step 4: 通过 kubectl 验证 CRD 创建**

Run: `kubectl get networktopology -n default`
Expected: 显示 test-topology-1

**Step 5: 验证前端列表是否显示 (Bug #1)**

访问 http://localhost:5173/topologies
Expected: 列表页显示 test-topology-1

**Step 6: 检查浏览器网络请求**

打开浏览器开发者工具 → Network 标签
观察: GET /api/v1/namespaces/default/networktopologies 请求
Expected: 
- 状态码 200
- 返回的 items 数组包含 test-topology-1

---

### Task 4: 测试删除 Topology 功能 (Bug #2 验证)

**Files:**
- Frontend: `frontend/src/pages/TopologyList.tsx`
- Frontend: `frontend/src/api/client.ts`
- Backend: `internal/controller/api/server.go`

**Step 1: 通过前端删除 Topology**

操作:
1. 在 /topologies 列表页找到 test-topology-1
2. 点击 "Delete" 按钮
3. 确认删除对话框

Expected: 
- 前端显示删除成功
- 列表中不再显示该 topology

**Step 2: 通过 API 验证删除**

Run: `curl -s http://localhost:8080/api/v1/namespaces/default/networktopologies/test-topology-1`
Expected: 404 Not Found 或错误响应

**Step 3: 通过 kubectl 验证删除**

Run: `kubectl get networktopology -n default`
Expected: 不再显示 test-topology-1

**Step 4: 验证相关 Pod 是否被删除**

Run: `kubectl get pods -n default -l kuro.io/topology=test-topology-1`
Expected: 没有 pods（或显示 No resources found）

---

### Task 5: 调试和修复 Bug #1 (列表不显示)

**如果 Task 3 Step 5 失败，执行此任务**

**Files:**
- Frontend: `frontend/src/stores/topologyStore.ts`
- Frontend: `frontend/src/api/client.ts`

**Step 1: 检查 API 返回格式**

Run: `curl -s http://localhost:8080/api/v1/namespaces/default/networktopologies`
Expected 格式:
```json
{
  "success": true,
  "data": {
    "items": [...],
    "totalCount": 1
  }
}
```

**Step 2: 检查前端 API 客户端响应处理**

查看 `frontend/src/api/client.ts` 中 `RealKuroApiClient.listTopologies` 方法
Expected: 正确解析 `response.data.items`

**Step 3: 检查 store 数据流**

在 `frontend/src/stores/topologyStore.ts` 中 `fetchTopologies` 方法添加日志:
```typescript
console.log('API response:', response);
```

**Step 4: 如果格式不匹配，修复代码**

根据实际 API 返回格式调整前端代码

**Step 5: 提交修复**

Run: `git add frontend/src/api/client.ts frontend/src/stores/topologyStore.ts`
Run: `git commit -m "fix(frontend): correct topology list data parsing"`

---

### Task 6: 调试和修复 Bug #2 (删除功能)

**如果 Task 4 失败，执行此任务**

**Files:**
- Frontend: `frontend/src/pages/TopologyList.tsx`
- Backend: `internal/controller/api/server.go`

**Step 1: 测试直接 API 删除**

Run: 
```bash
curl -X DELETE http://localhost:8080/api/v1/namespaces/default/networktopologies/test-topology-1
```
Expected: `{"success": true}`

**Step 2: 检查前端删除调用**

查看 `frontend/src/pages/TopologyList.tsx` 中 `handleDeleteTopology` 方法
Expected: 正确调用 `apiClient.deleteTopology(name, namespace)`

**Step 3: 检查后端删除处理**

查看 `internal/controller/api/server.go` 中 `deleteNetworkTopology` 方法
Expected: 使用 K8s client 正确删除 CRD

**Step 4: 如果删除后 Pod 未清理**

检查 NetworkTopology 是否配置了 ownerReferences 或 finalizers
Expected: Pod 应该有 ownerReference 指向 NetworkTopology，或 Controller 有清理逻辑

**Step 5: 提交修复**

Run: `git add <modified files>`
Run: `git commit -m "fix: ensure pods are deleted with topology CRD"`

---

### Task 7: 端到端测试 TrafficControl

**Files:**
- Frontend: `frontend/src/components/TrafficControlPanel.tsx`
- Backend: `internal/controller/api/server.go`

**Step 1: 创建测试 Topology**

Run: 
```bash
curl -X POST http://localhost:8080/api/v1/namespaces/default/networktopologies \
  -H "Content-Type: application/json" \
  -d '{
    "name": "tc-test-topology",
    "spec": {
      "nodeGroups": [
        {"name": "source", "replicas": 1, "image": "nicolaka/netshoot", "labels": {"role": "source"}},
        {"name": "dest", "replicas": 1, "image": "nicolaka/netshoot", "labels": {"role": "dest"}}
      ]
    }
  }'
```

**Step 2: 创建 TrafficControl**

Run:
```bash
curl -X POST http://localhost:8080/api/v1/namespaces/default/trafficcontrols \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test-tc",
    "spec": {
      "source": {"matchLabels": {"role": "source"}},
      "destination": {"matchLabels": {"role": "dest"}},
      "policy": {"bandwidth": "10Mbps", "latency": "50ms", "jitter": "10ms", "packetLoss": "0.5%"}
    }
  }'
```

**Step 3: 验证 TrafficControl 创建**

Run: `kubectl get trafficcontrol -n default`
Expected: 显示 test-tc

**Step 4: 清理测试资源**

Run:
```bash
kubectl delete trafficcontrol test-tc -n default
kubectl delete networktopology tc-test-topology -n default
```

---

## Success Criteria

- [ ] 后端环境成功启动
- [ ] 前端开发服务器成功启动
- [ ] 创建 Topology 后能在前端列表看到
- [ ] 创建 Topology 后能在 K8s 看到 CRD
- [ ] 删除 Topology 后前端列表不再显示
- [ ] 删除 Topology 后 K8s CRD 被删除
- [ ] 删除 Topology 后相关 Pod 被清理
- [ ] TrafficControl CRUD 操作正常

---

## Notes

- 使用 `browser-use` skill 进行前端自动化测试
- 使用 `kubectl` 命令验证 K8s 状态
- 所有修复需要 git commit
