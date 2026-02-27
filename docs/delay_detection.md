基于你提供的 eBPF 代码逻辑，想要用同一个 Telegraf 区分并分别测量 **SYS（系统）** 和 **SIM（模拟）** 流量是完全可行的。

代码中对流量分类的逻辑非常清晰，我们可以利用**端口分类策略**来让 Telegraf 发出不同属性的探测包。

### 流量分类原理解析

在你的 `tc.c` 中，流量分类（`is_sim_traffic` 的判定）主要分为两步：

1. **最高优先级：端口旁路 (Port Bypass)**
代码首先检查源或目的端口。如果属于 `PORT_SSH (22)`、`PORT_KUBELET (10250)` 或 `PORT_METRICS (9100)`，则直接被判定为 SYS 流量 (`is_sim_traffic = 0`)。
2. **次优先级：拓扑策略查找 (Policy Lookup)**
如果端口不是上述三个，代码会提取源 IP 和目的 IP，去 `topology_policy_map` 中查找。如果找到策略，则为 SIM 流量 (`is_sim_traffic = 1`)；如果找不到，依然归为 SYS 流量 (`is_sim_traffic = 0`)。

### Telegraf 配置方案

基于上述逻辑，你可以在 Telegraf 的 ConfigMap 中配置**两个** `net_response` 输入插件。一个强制走 SYS 规则，另一个走 SIM 规则，并给它们打上不同的标签（Tags）以便在 Grafana 中区分。

以下是具体的 Telegraf 配置示例：

```toml
# Telegraf 全局配置
[agent]
  interval = "10s"
  round_interval = true

# ==========================================
# 1. 测量 SYS (系统) 流量延迟
# ==========================================
# 原理：目标端口使用 9100，触发代码中的 is_system_port() 逻辑
[[inputs.net_response]]
  protocol = "tcp"
  # 探测目标 Pod 暴露的 9100 端口 (确保对端 Pod 允许 9100 端口连通)
  address = "<目标Pod的IP>:9100" 
  timeout = "3s"
  [inputs.net_response.tags]
    traffic_type = "sys"  # 打上 sys 标签

# ==========================================
# 2. 测量 SIM (模拟) 流量延迟
# ==========================================
# 原理：避开 22, 10250, 9100 端口，且要求源和目的 IP 存在于 topology_policy_map 中
[[inputs.net_response]]
  protocol = "tcp"
  # 探测目标 Pod 的业务端口，例如 8080
  address = "<目标Pod的IP>:8080"
  timeout = "3s"
  [inputs.net_response.tags]
    traffic_type = "sim"  # 打上 sim 标签

# ==========================================
# 输出到 Prometheus
# ==========================================
[[outputs.prometheus_client]]
  listen = ":9273"
  metric_version = 2

```

### ⚠️ 一个极其关键的避坑指南 (IP 解析问题)

注意你的 `tc.c` 代码注释：

> Scenario 2: Upload Control (Pod -> Host -> World)
> Hook Point: Pod eth0 -> Egress (Inside Pod Netns)

因为你的 Upload Hook 是挂载在 **Pod 内部的 eth0** 上的，在这个阶段，Kubernetes 的 Service IP (ClusterIP) **还没有被 kube-proxy 或 Cilium 转换为后端的真实 Pod IP**。

* **这意味着：** 如果 Telegraf 的 `address` 填的是一个常规的 `Service_Name:Port`，你的 eBPF 程序 `parse_ipv4` 解析出来的目的 IP 将是 **ClusterIP**，而不是真正的 Pod IP。
* **后果：** 这个 ClusterIP 绝对不在你的 `topology_policy_map` 里面，所以即使你使用了 8080 端口，这段流量依然会被判定为 **SYS 流量** (`is_sim_traffic = 0`)！

**解决方案：**
在 Telegraf 的 `address` 中，**绝对不能使用常规的 ClusterIP Service**。你必须使用：

1. **直接写死目标的 Pod IP**（仅用于临时测试）。
2. 或者，使用 Kubernetes 的 **Headless Service**（ClusterIP 设置为 None）。Headless Service 的 DNS 解析会直接返回真实的 Pod IP，这样 eBPF 才能正确拿到 `dst_ip` 并去 Map 中成功匹配到 SIM 策略。

---

当你部署好带有上述配置的 Telegraf 后，Prometheus 就会拉取到带有 `traffic_type="sys"` 和 `traffic_type="sim"` 两个标签的 `net_response_response_time_seconds` 指标。你就可以直观对比物理延迟注入和原生系统流量的差异了。

需要我为你提供一段配置 Headless Service 的 YAML 示例，确保 Telegraf 能够正确解析到目标 Pod IP 吗？
