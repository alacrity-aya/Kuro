# Grafana Dashboard Configuration Guide

This document explains how to configure Grafana monitoring dashboards for Kuro.

## Prerequisites

- Kubernetes cluster with Kuro Agent (DaemonSet) deployed
- Agent has exposed Prometheus metrics endpoint (`:8080/metrics`)

## Deploy Monitoring Stack

Use `deploy/quick-monitor.yaml` to deploy Prometheus + Grafana with one command:

```bash
kubectl apply -f deploy/quick-monitor.yaml
```

This command will create:
- `kuro-monitor` namespace
- Prometheus service (NodePort 30091)
- Grafana service (NodePort 30092)
- Kuro Agent metrics service discovery configuration

## Access Grafana

```bash
# Port forwarding (recommended)
kubectl port-forward -n kuro-monitor svc/grafana 30092:3000

# Or access NodePort directly
# http://<node-ip>:30092
```

Default credentials:
- Username: `admin`
- Password: `admin`

## Configure Prometheus Data Source

1. After logging into Grafana, go to **Configuration** → **Data Sources**
2. Click **Add data source**
3. Select **Prometheus**
4. Configure connection:
   - Name: `Kuro Prometheus`
   - URL: `http://prometheus:9090` (in-cluster service name)
   - Access: `Server (default)`
5. Click **Save & Test** to confirm connection is successful

## Create Kuro Dashboard

### Method 1: Manually Create Panels

#### 1. Bandwidth Monitoring Panel

**Query:**
```promql
sum(rate(kuro_pod_traffic_bytes_total{type="sim"}[5m])) by (pod, direction) * 8 / 1e6
```

**Visualization:** Time series
- Legend: `{{pod}} - {{direction}}`
- Unit: `Mbps`

#### 2. Latency Distribution Panel (P95/P99)

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

#### 3. Packet Loss Rate Panel

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

### Method 2: Import Dashboard JSON

Save the following JSON as `kuro-dashboard.json` and import:

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

Import steps:
1. Go to **Dashboards** → **Import**
2. Upload JSON file or paste content
3. Select Prometheus data source
4. Click **Import**

## Frontend Integration

Grafana Dashboard can be embedded in frontend pages via iframe:

```typescript
// Reference frontend/src/components/metrics/GrafanaEmbed.tsx
const iframeUrl = `${grafanaUrl}/d-solo/kuro-dashboard?orgId=1&refresh=5s&theme=dark&panelId=${panelId}`;
```

Supported embed modes:
- `/d/{uid}` - Full dashboard
- `/d-solo/{uid}?panelId={id}` - Single panel

## Common PromQL Queries

### Traffic Statistics

```promql
# Total traffic rate
sum(rate(kuro_pod_traffic_bytes_total[5m])) * 8 / 1e6

# Grouped by Pod
sum(rate(kuro_pod_traffic_bytes_total{type="sim"}[5m])) by (pod) * 8 / 1e6

# Grouped by direction
sum(rate(kuro_pod_traffic_bytes_total{direction="download"}[5m])) * 8 / 1e6
```

### Latency Statistics

```promql
# Average latency
rate(kuro_pod_latency_seconds_sum[5m]) / rate(kuro_pod_latency_seconds_count[5m])

# P50/P95/P99
histogram_quantile(0.50, sum(rate(kuro_pod_latency_seconds_bucket[5m])) by (le))
histogram_quantile(0.95, sum(rate(kuro_pod_latency_seconds_bucket[5m])) by (le))
histogram_quantile(0.99, sum(rate(kuro_pod_latency_seconds_bucket[5m])) by (le))
```

### Packet Loss Statistics

```promql
# Total packet loss rate
sum(rate(kuro_pod_drop_packets_total[5m])) / sum(rate(kuro_pod_traffic_packets_total[5m])) * 100

# Packet loss rate per Pod
sum(rate(kuro_pod_drop_packets_total[5m])) by (pod) 
  / sum(rate(kuro_pod_traffic_packets_total[5m])) by (pod) * 100
```

## Alert Configuration

Configure alert rules in Grafana:

1. Go to Dashboard → Panel → Edit → Alert
2. Add alert rule:

**Packet Loss Rate Alert:**
```yaml
Condition: WHEN last() OF query(A) IS ABOVE 1
Evaluation: Every 30 seconds
Message: Kuro Pod {{pod}} packet loss rate exceeds 1%
```

**Latency Alert:**
```yaml
Condition: WHEN last() OF query(A) IS ABOVE 0.1
Evaluation: Every 30 seconds
Message: Kuro Pod {{pod}} P95 latency exceeds 100ms
```

## Troubleshooting

### Prometheus Cannot Scrape Metrics

```bash
# Check Agent Service
kubectl get svc -n kuro-system kuro-agent-metrics

# Check Agent Pod endpoints
kubectl get endpoints -n kuro-system kuro-agent-metrics

# View Prometheus targets
# http://localhost:30091/targets
```

### Grafana Cannot Connect to Prometheus

```bash
# Check Prometheus service
kubectl get svc -n kuro-monitor prometheus

# Test connection from Grafana Pod
kubectl exec -n kuro-monitor -it deploy/grafana -- \
  curl http://prometheus:9090/-/healthy
```

## Reference Links

- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Documentation](https://grafana.com/docs/)
- [Kuro Metrics Architecture](../docs/design.md)