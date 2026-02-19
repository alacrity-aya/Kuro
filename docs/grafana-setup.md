# Grafana Dashboard 配置指南

本文档说明如何为 Kuro 配置 Grafana 监控仪表板。

## 前提条件

- Kubernetes 集群已部署 Kuro Agent (DaemonSet)
- Agent 已暴露 Prometheus metrics 端点 (`:8080/metrics`)

## 部署监控栈

使用 `deploy/quick-monitor.yaml` 一键部署 Prometheus + Grafana：

```bash
kubectl apply -f deploy/quick-monitor.yaml
```

该命令会创建：
- `kuro-monitor` namespace
- Prometheus 服务 (NodePort 30091)
- Grafana 服务 (NodePort 30092)
- Kuro Agent metrics 服务发现配置

## 访问 Grafana

```bash
# 端口转发（推荐）
kubectl port-forward -n kuro-monitor svc/grafana 30092:3000

# 或直接访问 NodePort
# http://<node-ip>:30092
```

默认凭据：
- 用户名: `admin`
- 密码: `admin`

## 配置 Prometheus 数据源

1. 登录 Grafana 后，进入 **Configuration** → **Data Sources**
2. 点击 **Add data source**
3. 选择 **Prometheus**
4. 配置连接：
   - Name: `Kuro Prometheus`
   - URL: `http://prometheus:9090` (集群内服务名)
   - Access: `Server (default)`
5. 点击 **Save & Test** 确认连接成功

## 创建 Kuro Dashboard

### 方式一：手动创建面板

#### 1. 带宽监控面板

**Query:**
```promql
sum(rate(kuro_pod_traffic_bytes_total{type="sim"}[5m])) by (pod, direction) * 8 / 1e6
```

**Visualization:** Time series
- Legend: `{{pod}} - {{direction}}`
- Unit: `Mbps`

#### 2. 延迟分布面板 (P95/P99)

**Query (P95):**
```promql
histogram_quantile(0.95, sum(rate(kuro_pod_latency_seconds_bucket[5m])) by (pod, le))
```

**Query (P99):**
```promql
histogram_quantile(0.99, sum(rate(kuro_pod_latency_seconds_bucket[5m])) by (pod, le))
```

**Visualization:** Time series
- Legend: `{{pod}} P95`
- Unit: `seconds`

#### 3. 丢包率面板

**Query:**
```promql
sum(rate(kuro_pod_drop_packets_total[5m])) by (pod) 
  / sum(rate(kuro_pod_traffic_packets_total[5m])) by (pod) * 100
```

**Visualization:** Stat
- Unit: `percent (0-100)`
- Thresholds: 
  - Green: 0 - 0.1
  - Yellow: 0.1 - 1.0
  - Red: > 1.0

### 方式二：导入 Dashboard JSON

将以下 JSON 保存为 `kuro-dashboard.json` 并导入：

```json
{
  "dashboard": {
    "title": "Kuro Network Metrics",
    "uid": "kuro-dashboard",
    "panels": [
      {
        "title": "Bandwidth (Mbps)",
        "type": "timeseries",
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0},
        "targets": [
          {
            "expr": "sum(rate(kuro_pod_traffic_bytes_total{type=\"sim\"}[5m])) by (pod, direction) * 8 / 1e6",
            "legendFormat": "{{pod}} - {{direction}}"
          }
        ]
      },
      {
        "title": "Latency P95/P99",
        "type": "timeseries",
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0},
        "targets": [
          {
            "expr": "histogram_quantile(0.95, sum(rate(kuro_pod_latency_seconds_bucket[5m])) by (le))",
            "legendFormat": "P95"
          },
          {
            "expr": "histogram_quantile(0.99, sum(rate(kuro_pod_latency_seconds_bucket[5m])) by (le))",
            "legendFormat": "P99"
          }
        ]
      },
      {
        "title": "Packet Loss Rate",
        "type": "stat",
        "gridPos": {"h": 4, "w": 6, "x": 0, "y": 8},
        "targets": [
          {
            "expr": "sum(rate(kuro_pod_drop_packets_total[5m])) / sum(rate(kuro_pod_traffic_packets_total[5m])) * 100"
          }
        ]
      }
    ]
  }
}
```

导入步骤：
1. 进入 **Dashboards** → **Import**
2. 上传 JSON 文件或粘贴内容
3. 选择 Prometheus 数据源
4. 点击 **Import**

## 前端集成

Grafana Dashboard 可通过 iframe 嵌入前端页面：

```typescript
// 参考 frontend/src/components/metrics/GrafanaEmbed.tsx
const iframeUrl = `${grafanaUrl}/d-solo/kuro-dashboard?orgId=1&refresh=5s&theme=dark&panelId=${panelId}`;
```

支持的 embed 模式：
- `/d/{uid}` - 完整仪表板
- `/d-solo/{uid}?panelId={id}` - 单个面板

## 常用 PromQL 查询

### 流量统计

```promql
# 总流量速率
sum(rate(kuro_pod_traffic_bytes_total[5m])) * 8 / 1e6

# 按 Pod 分组
sum(rate(kuro_pod_traffic_bytes_total{type="sim"}[5m])) by (pod) * 8 / 1e6

# 按方向分组
sum(rate(kuro_pod_traffic_bytes_total{direction="download"}[5m])) * 8 / 1e6
```

### 延迟统计

```promql
# 平均延迟
rate(kuro_pod_latency_seconds_sum[5m]) / rate(kuro_pod_latency_seconds_count[5m])

# P50/P95/P99
histogram_quantile(0.50, sum(rate(kuro_pod_latency_seconds_bucket[5m])) by (le))
histogram_quantile(0.95, sum(rate(kuro_pod_latency_seconds_bucket[5m])) by (le))
histogram_quantile(0.99, sum(rate(kuro_pod_latency_seconds_bucket[5m])) by (le))
```

### 丢包统计

```promql
# 总丢包率
sum(rate(kuro_pod_drop_packets_total[5m])) / sum(rate(kuro_pod_traffic_packets_total[5m])) * 100

# 按 Pod 丢包率
sum(rate(kuro_pod_drop_packets_total[5m])) by (pod) 
  / sum(rate(kuro_pod_traffic_packets_total[5m])) by (pod) * 100
```

## 告警配置

在 Grafana 中配置告警规则：

1. 进入 Dashboard → 面板 → Edit → Alert
2. 添加告警规则：

**丢包率告警:**
```yaml
条件: WHEN last() OF query(A) IS ABOVE 1
评估: 每 30 秒
消息: Kuro Pod {{pod}} 丢包率超过 1%
```

**延迟告警:**
```yaml
条件: WHEN last() OF query(A) IS ABOVE 0.1
评估: 每 30 秒
消息: Kuro Pod {{pod}} P95 延迟超过 100ms
```

## 故障排查

### Prometheus 无法抓取 metrics

```bash
# 检查 Agent Service
kubectl get svc -n kuro-system kuro-agent-metrics

# 检查 Agent Pod endpoints
kubectl get endpoints -n kuro-system kuro-agent-metrics

# 查看 Prometheus targets
# http://localhost:30091/targets
```

### Grafana 无法连接 Prometheus

```bash
# 检查 Prometheus 服务
kubectl get svc -n kuro-monitor prometheus

# 从 Grafana Pod 测试连接
kubectl exec -n kuro-monitor -it deploy/grafana -- \
  curl http://prometheus:9090/-/healthy
```

## 参考链接

- [Prometheus 文档](https://prometheus.io/docs/)
- [Grafana 文档](https://grafana.com/docs/)
- [Kuro Metrics 架构](../docs/design.md)
