# Kuro Simulation Platform CRD Detailed Design

**Version:** v1alpha1

**API Group:** `simulation.kuro.io`

This document defines two core Custom Resource Definitions (CRDs):

1. **NetworkTopology**: Defines physical topology, node resources, and user-defined logic (satisfying general programmability).
2. **TrafficControl**: Defines network link quality (bandwidth, latency, loss, etc.) and supports dynamic flow control.

---

## 1. Resource Definition: `NetworkTopology`

This resource describes the "static structure" of a simulation experiment. It defines not only the number of nodes but also allows users to inject code via the `userProgram` field, achieving the "general programmability" required in `design.md` and `requirement.md`.

### 1.1 YAML Example

```yaml
apiVersion: simulation.kuro.io/v1alpha1
kind: NetworkTopology
metadata:
  name: drone-swarm-experiment
  namespace: kuro-experiment
spec:
  nodeGroups:
    - name: drone-follower
      replicas: 50
      image: kuro-registry/drone-base:v1.2
      
      # [Key Feature] General Programmability Interface
      # The low-code platform fills this with Python/Lua/JS code written by the user in the UI.
      userProgram:
        filename: "algorithm.py"
        mountPath: "/app/scripts/algorithm.py"
        source: |
          import time
          def run():
              while True:
                  print("Drone follower logic running...")
                  time.sleep(1)
          if __name__ == "__main__":
              run()
      
      # Override container start command to execute user code
      command: ["python3", "/app/scripts/algorithm.py"]

      # Resource limits
      resources:
        limits:
          cpu: "500m"
          memory: "512Mi"
      
      # Auto-injected labels (used for TrafficControl selection)
      labels:
        role: follower
        team: red

```

### 1.2 Field Details

| Field Path | Type | Required | Description |
| --- | --- | --- | --- |
| `spec.nodeGroups` | Array | Yes | List of node groups (e.g., drones, ground stations). |
| `nodeGroups[].name` | String | Yes | Group name; used as a prefix for generated Deployments and Pods. |
| `nodeGroups[].replicas` | Integer | Yes | Number of nodes. The Controller creates corresponding Pods. |
| `nodeGroups[].image` | String | Yes | Base image. Should include Agent SDK and runtime (e.g., Python). |
| `nodeGroups[].userProgram` | Object | No | **Core programmability field.** Defines code to be injected. |
| `userProgram.source` | String | Yes | Actual code content. Captured from the low-code editor. |
| `userProgram.mountPath` | String | Yes | Absolute path where the code is mounted inside the container. |
| `nodeGroups[].command` | String[] | No | Startup command, usually pointing to the `mountPath`. |
| `nodeGroups[].labels` | Map | No | Custom labels used by `TrafficControl` for filtering. |

### 1.3 Behind the Scenes: How it works

When the low-code platform submits a `NetworkTopology` YAML, the **Topology Controller** executes the following Reconcile loop:

1. **Code Injection Analysis**: Controller reads the `userProgram.source` content.
2. **Generate Configuration (ConfigMap)**:
* Creates a K8s ConfigMap to store the source code.
* *Optimization*: Uses a Hash of the code content as a suffix (e.g., `drone-config-a1b2c`) to trigger rolling updates if the code changes.


3. **Build Deployment**:
* Creates a K8s Deployment.
* **Mounting**: Mounts the ConfigMap as a Volume at the specified `mountPath`.
* **Injection**: Automatically adds the `kuro.io/sim-node: "true"` label so the DaemonSet (Agent) can identify and intercept traffic for these Pods.


4. **Status Sync**: Monitors Pod readiness and updates the CRD `Status` (e.g., "50/50 Nodes Ready") for UI feedback.

---

## 2. Resource Definition: `TrafficControl`

This resource describes the "physical laws of the network" between nodes. It uses **Label Selectors** to decouple from specific IP addresses, making it ideal for dynamic simulation environments.

### 2.1 YAML Example

```yaml
apiVersion: simulation.kuro.io/v1alpha1
kind: TrafficControl
metadata:
  name: weak-signal-area
  namespace: kuro-experiment
spec:
  priority: 100  # Priority to resolve conflicts
  
  # Traffic Source: All drones in the "red team"
  source:
    matchLabels:
      role: follower
      team: red
  
  # Traffic Destination: Ground station
  destination:
    matchLabels:
      role: ground-station

  # Link Physical Properties
  policy:
    bandwidth: "5Mbps"
    latency: "100ms"
    jitter: "20ms"
    packetLoss: "0.5%"  # 0.5% packet loss rate

```

### 2.2 Field Details

| Field Path | Type | Required | Description |
| --- | --- | --- | --- |
| `spec.priority` | Integer | No | Rule priority. Higher numbers take precedence for overlapping rules. |
| `spec.source` | LabelSelector | Yes | Defines which Pods' outgoing traffic is restricted. |
| `spec.destination` | LabelSelector | Yes | Defines which Pods' incoming traffic is restricted. |
| `spec.policy` | Object | Yes | Network parameters mapped to the eBPF layer. |
| `policy.bandwidth` | String | No | Bandwidth limit (Kbps, Mbps, Gbps). |
| `policy.latency` | String | No | Base latency (ms, us). |
| `policy.jitter` | String | No | Jitter amplitude (Normal distribution). |
| `policy.packetLoss` | String | No | Packet loss rate (percentage string). |

### 2.3 Behind the Scenes: How it works

When a user adjusts sliders on the UI and updates the `TrafficControl` CRD, the **Traffic Controller** performs the following:

1. **Selector Resolution**: Queries the K8s API to find current Pod IPs for both source and destination selectors.
2. **Cartesian Product Calculation**: Computes all affected link pairs (e.g., Pod A -> Pod C, Pod B -> Pod C).
3. **Unit Normalization**: Converts human-readable strings (100ms) to system units (100,000,000 ns).
4. **gRPC Dispatch**:
* For each link, the Controller identifies the host Node of the source Pod.
* Calls the `ApplyLinkPolicy` gRPC interface on that Node's **Agent**.


5. **eBPF Enforcement**: The Agent updates local eBPF Maps. When data leaves the Pod, the eBPF program intercepts it at the Egress point and applies rate limiting/latency.

---

## 3. The Big Picture: System Workflow

To satisfy the "User-friendly Topology" and "Low-Code Platform" requirements:

```text
+-----------------+       +--------------------------+       +-------------------------+
|   Web UI / IDE  |       |   K8s API Server         |       |   Kuro Controller       |
| (Low-Code Tool) |       | (CRD Storage)            |       | (The Brain)             |
+--------+--------+       +------------+-------------+       +-----------+-------------+
         |                             |                                 |
         | 1. Generate YAML            |                                 |
         +---------------------------->| 2. Store NetworkTopology        |
         |                             |    Store TrafficControl         |
         |                             |                                 |
         |                             +-------------------------------->| 3. Watch Event
         |                             |                                 |
         |                             |                                 | 4. Reconcile
         |                             |                                 |
         |                             |<--------------------------------+
         |                             | 5. Create Deployment & ConfigMap|
         |                             |                                 |
+--------v--------+                    |                                 |
|  K8s Cluster    |                    |                                 |
|                 |                    |                                 |
| +-------------+ |  6. Schedule Pods  |                                 | 7. Resolve IPs &
| | Node 1      | |<-------------------+                                 |    Calc Policies
| |  [Agent] <==|=|======================================================|
| |    ^        | |      8. gRPC: ApplyLinkPolicy(Src=PodA, Dst=PodB)    |
| |    |        | |                                                      |
| |  [Pod A]    | |                                                      |
| | (User Code) | |                                                      |
| +-------------+ |                                                      |
+-----------------+                                                      |
                                                                         |
                                                                         |
                                                                         v
                                                                 +----------------+
                                                                 | Node 2 [Agent] |
                                                                 +----------------+

```

---

## Key Design Advantages

* **True Infrastructure as Code (IaC)**: The entire experiment state (code, topology, network) is stored in CRDs, allowing for easy "Save," "Load," and "Version Control."
* **Dynamic Responsiveness**: Users can modify `TrafficControl` while the experiment is running. The Controller syncs changes to eBPF in milliseconds.
* **Zero Intrusiveness**: User code is injected via ConfigMaps. There is no need to rebuild Docker images, drastically shortening the "Modify -> Retry" feedback loop.
