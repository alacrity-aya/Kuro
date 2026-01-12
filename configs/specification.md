# Kuro Network Topology Configuration (v2.1)

## Overview

The `NetworkTopology` resource is the core configuration file for the Kuro Network Emulator. It defines the network graph, link quality (QoS), and traffic isolation policies for a specific experiment.

### Key Concepts

* **Scope**: A topology is strictly bound to a Kubernetes `Namespace`. One cluster can host multiple experiments in different namespaces.
* **Traffic Classes**:
* **Simulation Traffic**: Traffic matching defined `links`. Subject to specific QoS (bandwidth, latency, loss).
* **Background Traffic**: Traffic NOT matching any link rules (e.g., K8s health checks, SSH, logs). Subject to a global or node-level rate limit to prevent interference.


* **Selector Modes**: Supports both manual port/protocol matching and automatic IP-based topology perception.

---

## File Structure

```yaml
apiVersion: kuro.io/v1alpha1
kind: NetworkTopology
metadata:
  name: <string>
  namespace: <string>
spec:
  defaults: <Object>
  nodes: <List>
  links: <List>

```

### 1. Metadata

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | string | Yes | Unique name for this topology configuration (e.g., `experiment-01`). |
| `namespace` | string | Yes | **Critical.** The Kubernetes Namespace this experiment belongs to. The Controller will only manage Pods within this namespace. |

---

### 2. Spec: Global Defaults (`spec.defaults`)

Defines the baseline network capabilities and safety limits for all nodes in the experiment. These can be overridden on a per-node basis.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `physical_capacity` | string | `1Gbps` | The theoretical physical interface capacity of the node. Used by the Controller for **admission control** (validating if requested bandwidth > physical) and calculating background traffic headroom. |
| `background_rate` | string | `unlimited` | The bandwidth limit for **non-simulation traffic**. Setting this protects simulation traffic from being starved by heavy background processes (e.g., log shipping). |
| `background_burst` | string | `100KB` | The burst size for background traffic. |

---

### 3. Spec: Nodes (`spec.nodes`)

Defines the list of Kubernetes Pods participating in the experiment.

| Field | Type | Description |
| --- | --- | --- |
| `name` | string | The exact name of the Kubernetes Pod (`metadata.name`). Must exist in the declared `namespace`. |
| `config` | Object | *(Optional)* Node-level overrides for global defaults. |

**`nodes[].config` Structure:**

| Field | Type | Description |
| --- | --- | --- |
| `physical_capacity` | string | Overrides the global `physical_capacity` for this specific node (e.g., for a high-performance gateway node). |
| `background_rate` | string | Overrides the global `background_rate` for this node. |

---

### 4. Spec: Links (`spec.links`)

Defines a **unidirectional** edge in the network graph from a `source` Pod to a `target` Pod.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `source` | string | Yes | The name of the source Pod. |
| `target` | string | Yes | The name of the destination Pod. |
| `selector` | Object | Yes | Rules for identifying which traffic belongs to this link. |
| `qos` | Object | Yes | Quality of Service parameters (bandwidth, latency, loss, etc.). |

#### 4.1 Link Selector (`links[].selector`)

Determines how traffic is classified as "Simulation Traffic".

| Field | Type | Valid Values | Description |
| --- | --- | --- | --- |
| `mode` | string | `topology_aware` | `manual` |
| `protocol` | string | `TCP`, `UDP`, `ICMP`, `ALL` | *(Required if mode is `manual`)*. The L4 protocol to match. |
| `dest_port` | int | 1-65535 | *(Required if mode is `manual`)*. The destination port to match. |

#### 4.2 Link QoS (`links[].qos`)

Defines the network characteristics applied to the matched traffic.

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `bandwidth` | string | - | **Rate Limit**. The maximum speed for this link (e.g., `10Mbps`, `1Gbps`). |
| `burst` | string | `bandwidth/10` | **Bucket Size**. The maximum amount of data allowed to pass in a burst. Essential for high-bandwidth TCP throughput. (e.g., `200KB`, `1MB`). |
| `shaping_type` | string | `tbf` | **Algorithm**. <br>

<br>`tbf`: Token Bucket Filter (Smooth shaping).<br>

<br>`policing`: Hard drop (No buffer).<br>

<br>`htb`: Hierarchical Token Bucket. |
| `latency` | string | `0ms` | Added delay (e.g., `50ms`). |
| `jitter` | string | `0ms` | Random variation in latency (e.g., `10ms`). |
| `loss` | string | `0%` | Packet loss rate (e.g., `0.5%`, `1%`). |

---

## Complete Configuration Example

```yaml
apiVersion: kuro.io/v1alpha1
kind: NetworkTopology
metadata:
  name: "experiment-drone-cluster"
  namespace: "kuro-experiment-A"

spec:
  # 1. Global Safety Limits
  defaults:
    physical_capacity: "1000Mbps" # Physical limit
    background_rate: "900Mbps"    # Limit for SSH/Logs/K8s-probes
    background_burst: "100KB"

  # 2. Participating Nodes
  nodes:
    - name: "drone-01"
    - name: "drone-02"
    - name: "ground-station"
      # Override: Station has a 10G card
      config:
        physical_capacity: "10Gbps"
        background_rate: "9Gbps"

  # 3. Network Edges
  links:
    # Scenario A: Automatic IP-based routing (Preferred)
    # Traffic from drone-01 -> drone-02 is limited to 20Mbps
    - source: "drone-01"
      target: "drone-02"
      selector:
        mode: "topology_aware"
      qos:
        bandwidth: "20Mbps"
        burst: "100KB"
        latency: "10ms"
        jitter: "2ms"
        loss: "0.1%"

    # Scenario B: Manual Port-based routing
    # Only UDP traffic on port 8080 is limited.
    # SSH (TCP 22) between these pods will fall back to 'background_rate'
    - source: "drone-02"
      target: "ground-station"
      selector:
        mode: "manual"
        protocol: "UDP"
        dest_port: 8080
      qos:
        bandwidth: "5Mbps"
        burst: "20KB"
        shaping_type: "tbf"
        latency: "100ms"

```
