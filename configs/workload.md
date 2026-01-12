This document outlines the specification for the **Experiment Workload Configuration (v1alpha1)**. It addresses the requirements for identity stability, network visibility, and kernel privileges required for high-fidelity network emulation on Kubernetes.

---

# Experiment Workload Configuration (v1alpha1)

## 1. Overview

The `ExperimentWorkload` resource defines the **infrastructure layer** of a network simulation experiment. It abstracts the complexity of Kubernetes native resources (StatefulSets, Services, SecurityContexts) to provide a simple interface for defining simulation nodes.

**Core Responsibilities:**

1. **Identity Stability**: Automatically generates `StatefulSets` to ensure Pod names are predictable and fixed (e.g., `drone-0`, `drone-1`).
2. **Network Visibility**: Automatically creates companion **Headless Services** to ensure every Pod has a unique DNS record and exposes its real IP address.
3. **Privilege Injection**: Automatically injects `NET_ADMIN` capabilities into containers, enabling the Kuro Agent to manipulate the kernel network stack (TC/Netem).

---

## 2. File Structure

```yaml
apiVersion: kuro.io/v1alpha1
kind: ExperimentWorkload
metadata:
  name: <string>
  namespace: <string>
spec:
  components: <List>

```

### 2.1 Metadata

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | string | Yes | The unique name of this workload definition (e.g., `drone-cluster-infra`). |
| `namespace` | string | Yes | **Critical.** Must match the namespace defined in your `NetworkTopology` configuration. |

### 2.2 Spec: Components (`spec.components`)

An experiment often consists of different roles (e.g., a swarm of drones + a ground station). Each `component` defined here translates to **one StatefulSet** and **one Headless Service**.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | string | Yes | The base name for the component. Pods will be named `<name>-<index>` (e.g., `drone-0`, `drone-1`). |
| `replicas` | int | Yes | The number of nodes to deploy for this component. |
| `image` | string | Yes | The container image to run (e.g., `nicolaka/netshoot`). |
| `command` | string[] | No | Startup command. Defaults to `["sleep", "infinity"]`. |
| `args` | string[] | No | Arguments for the command. |
| `env` | map | No | Environment variables to inject. |
| `resources` | object | No | Kubernetes resource requests/limits (CPU/Memory). |

---

## 3. Translation Logic (Behind the Scenes)

The Kuro Controller translates the `ExperimentWorkload` configuration into native Kubernetes resources to satisfy strict emulation requirements.

### Requirement 1: Identity Stability

* **Input**: `name: drone`, `replicas: 2`
* **Output**: A Kubernetes `StatefulSet` named `drone`.
* **Result**: Pods are created with fixed, deterministic names: `drone-0` and `drone-1`. This allows the Topology configuration to reference them explicitly.

### Requirement 2: Network Visibility (Headless Service)

* **Input**: Implicit in the creation of any component.
* **Output**: A Kubernetes Service with `clusterIP: None`.
* **Result**: DNS lookups for `drone-0.drone` resolve directly to the **Pod's Real IP** (e.g., `10.244.1.5`) instead of a virtual Service IP. This enables the eBPF/TC layer to correctly identify and shape traffic destined for specific simulation nodes.

### Requirement 3: Kernel Privileges

* **Input**: Implicit.
* **Output**: The Pod specification includes:
```yaml
securityContext:
  capabilities:
    add: ["NET_ADMIN"]

```


* **Result**: The container has permission to modify network interfaces and queuing disciplines (qdiscs), which is required for traffic shaping.

---

## 4. Complete Configuration Examples

### 4.1 Workload Configuration (`01-experiment-workloads.yaml`)

This file creates the physical containers.

```yaml
apiVersion: kuro.io/v1alpha1
kind: ExperimentWorkload
metadata:
  name: "drone-experiment-infra"
  # Must match the namespace in the topology file
  namespace: "kuro-experiment-A"
spec:
  components:
    # Group 1: Drone Swarm (Pods: drone-0, drone-1, drone-2)
    - name: "drone"
      replicas: 3
      image: "kuro-drone-app:v1"
      command: ["/app/start_drone.sh"]
      env:
        ROLE: "follower"
      resources:
        limits:
          cpu: "500m"
          memory: "512Mi"

    # Group 2: Ground Station (Pod: ground-station-0)
    # Using StatefulSet even for 1 replica ensures the name is fixed (-0)
    - name: "ground-station"
      replicas: 1
      image: "kuro-station-app:v2"
      command: ["/app/start_station.sh"]
      resources:
        limits:
          cpu: "2000m"
          memory: "4Gi"

```

### 4.2 topology Configuration (`02-experiment-topology.yaml`)

This file connects the containers created above. Note how it references the generated names (`drone-0`, `ground-station-0`).

```yaml
apiVersion: kuro.io/v1alpha1
kind: NetworkTopology
metadata:
  name: "drone-experiment-topo"
  namespace: "kuro-experiment-A"
spec:
  defaults:
    physical_capacity: "1000Mbps"
    background_rate: "900Mbps"

  nodes:
    # Reference the fixed names generated by the Workload
    - name: "drone-0"
    - name: "drone-1"
    - name: "drone-2"
    - name: "ground-station-0"

  links:
    # Simulation Link: drone-0 -> drone-1
    - source: "drone-0"
      target: "drone-1"
      selector:
        # Automatically resolves drone-1's IP to distinguish
        # simulation traffic from background traffic
        mode: "topology_aware"
      qos:
        bandwidth: "20Mbps"
        burst: "50KB"
        latency: "50ms"

```
