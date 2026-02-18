**Document Overview**
This document outlines the complete system path, spanning from the underlying eBPF Data Plane to the upper Control Plane.

---

#### I. High-Level Architecture Design

The project adopts an architecture that separates the **Control Plane** from the **Data Plane**, running atop a Kubernetes cluster.

* **Architecture Pattern:** Hub-and-Spoke.
* **Communication Protocols:** gRPC (bi-directional streaming) is used for control instructions; HTTP is used for scraping monitoring metrics.

**1. Component Roles**

* **Simulation Controller (The Brain):** Deployed as a single instance (or high-availability replicas). It is responsible for parsing user topologies, scheduling K8s resources, calculating routing and bandwidth policies, and issuing them to Agents via gRPC.
* **Node Agent (The Hands and Feet):** Deployed as a DaemonSet, running on every K8s physical node. It handles network hooking for local Pods, eBPF program mounting, flow control execution, and data collection.
* **eBPF Kernel Layer (The Muscle):** Programs running in kernel space (TC, XDP) that execute the actual packet interception, shaping, and statistics collection.

---

#### II. Data Plane Details (eBPF)

This section details the implementation of the project's core challenge: traffic control and isolation. The code resides primarily in `bpf/tc.c` and `bpf/map.h`.

**1. Hook Points**

To achieve bidirectional control, Traffic Control (TC) programs are mounted on both ends of the Veth Pair:

* **Download (Host -> Pod):** Mounted at the Egress point of the host-side Veth interface. Program: `handle_edt_download`.
* **Upload (Pod -> Host):** Mounted at the Egress point of the Pod-side Veth interface (eth0 inside the Pod). Program: `handle_edt_upload`.
* **Ingress Protection:** Mounted at the XDP point of the host's physical NIC (eth0). Program: `handle_xdp_ingress`.

**2. Traffic Isolation Mechanism (Sim vs. Sys)**

This addresses the challenge of separating simulation traffic from system/business traffic. Instead of simple packet dropping, priority-based scheduling is employed.

* **Identification Mechanism:** Uses `simulation_peers_map` (a Hash Map).
* **Upload:** Checks the destination IP (`dst_ip`). If the destination is in the whitelist -> Sim; otherwise -> Sys.
* **Download:** Checks the source IP (`src_ip`). If the source is in the whitelist -> Sim; otherwise -> Sys.


* **Policy Execution:**
* **Sim Traffic:** Marked with `skb->priority = 1`. Strict Earliest Departure Time (EDT) algorithms are executed for rate limiting.
* **Sys Traffic:** Marked with `skb->priority = 0`. Packets are not dropped but have added latency. The code forces business traffic to queue behind simulation traffic in the physical NIC's FQ (Fair Queueing) scheduler by setting `skb->tstamp = now + SYS_LATENCY_OFFSET_NS` (e.g., 3ms).


* **Configuration Parameters:** Each Pod possesses four independent rate parameters (SimUp, SimDown, SysUp, SysDown).

**3. Traffic Shaping Algorithm**

Traditional Token Buckets are replaced with EDT (Earliest Departure Time) for shaping.

* **Principle:** Based on packet size and configured bandwidth, the theoretical transmission timestamp (`t_send`) is calculated and written into `skb->tstamp`. The kernel's `sch_fq` qdisc sends the packet precisely according to this timestamp.
* **Advantages:** Nanosecond-level precision, lower CPU overhead compared to traditional queues, and perfect support for TCP pacing.
* **Code Implementation:** The `throttle_flow` function maintains the `edt_state` (last send time) and ensures concurrency safety via spinlocks.

**4. Status Data Collection (Observability)**

* **Technology:** Uses `BPF_MAP_TYPE_PERCPU_HASH` to avoid lock contention.
* **Metrics:**
* `packets/bytes`: Successfully passed traffic.
* `drop_packets/drop_bytes`: Traffic dropped by EDT due to bandwidth limits (crucial for verifying simulation experiments).
* `latency_hist`: Latency histogram recording the distribution of delays introduced by eBPF shaping.



---

#### III. Control Plane Details (Controller & Agent)

This section is being refactored into a gRPC architecture to meet scalability and topology description requirements.

**1. Communication Protocol (`api/v1/simulation.proto`)**

* **Pattern:** The Agent actively connects to the Controller (Client-Side Streaming / Bi-directional).
* **Core Messages:**
* `Heartbeat`: Agent reports liveness status and the number of managed Pods.
* `PodLifecycleEvent`: Agent detects a newly started local Pod and reports its IP and Info.
* `SyncPeerWhitelist`: Controller issues the global IP whitelist (replacing inefficient peer_watcher broadcasts).
* `ApplyPodPolicy`: Controller issues specific rate-limiting rules.



**2. Agent Internal Logic (`internal/agent`)**

The Agent is a stateless executor deployed with `hostNetwork: true`.

* **Local Watcher:** Listens for local K8s Pod events. Upon detecting a Pod with specific labels, it retrieves its Netns handle.
* **BPF Manager:** Responsible for compiling and loading BPF programs and managing Maps (CRUD).
* It enters the Pod's Namespace to mount Upload programs.
* It maintains `rate_map` and `simulation_peers_map`.


* **Metrics Server:** Exposes `:8080/metrics`, providing data in Prometheus format.

**3. Controller Logic (`internal/controller`)**

* **Topology Parsing:** Reads user YAML topologies (Nodes, Links).
* **Resource Scheduling:** Converts logical nodes into K8s Deployments.
* **Global Mapping:** Maintains the mapping relationship of PodIP <-> Node <-> LogicID.
* **Policy Calculation:**
* Example: User defines A -> B bandwidth as 10Mbps.
* Controller finds Agent for A and issues `ApplyPodPolicy(SimUpload=10Mbps)`.
* Controller finds Agent for B and issues `ApplyPodPolicy(SimDownload=10Mbps)`.



---

#### IV. Summary of Solutions to Key Difficulties

**1. Handling "Different Bandwidths per Connection"**

* **Solution:** eBPF Map (`rate_map`) uses `ifindex` as the Key. Each Pod interface possesses independent configuration items in the Map. The Controller dynamically updates the Map based on the topology file to change bandwidth in real-time without restarting Pods.

**2. Handling "Coexistence of Simulation and Business Traffic"**

* **Solution:**
* **Egress:** TC EDT + Priority/Timestamp Offset. Sim traffic is sent with priority; Sys traffic is deferred.
* **Ingress:** XDP Token Bucket. At the physical NIC entrance, Sys traffic is rate-limited (to protect CPU), while Sim traffic is unconditionally passed (to avoid affecting experimental results).



**3. Data Storage**

* **Time-Series Data (Metrics):** Uses VictoriaMetrics. Agents expose `/metrics`, and VM automatically discovers and scrapes them via K8s SD. This solves high-frequency real-time data writing and compression storage.
* **Topology/Metadata:** Uses PostgreSQL or MySQL to store user-designed topology structures, node attributes, and experimental records.

**4. GUI Display**

* **Technology Stack:**
* 2D Topology: React Flow or AntV X6.
* 3D Scenes: Cesium.js (geospatial, e.g., drones) or Three.js (datacenter/microservices).


* **Data Flow:** The frontend queries the Controller via API Gateway for topology structures and directly queries VictoriaMetrics/Prometheus for real-time traffic and latency data for rendering.

---

#### V. Workflow

1. The user uploads a topology file (YAML) via the Web platform.
2. The Controller parses the topology and calls the K8s API to create required Pods (e.g., 100 Pods).
3. The K8s Scheduler assigns Pods to various Nodes.
4. The Node Agent detects a local Pod start:
* Mounts eBPF programs.
* Reports `PodEvent(IP=10.0.1.x, Name=Drone-1)` to the Controller via gRPC.


5. Once the Controller receives all Pod IPs:
* Generates a global whitelist and pushes it via gRPC to all Agents -> Agents update BPF Maps.
* Calculates the bandwidth for each Pod based on topology link rules and pushes it via gRPC to corresponding Agents -> Agents update `rate_map`.


6. **Simulation Begins:**
* Business programs within Pods (e.g., drone algorithms) start communicating.
* eBPF performs precise rate limiting at the kernel layer.
* Agents collect Metrics.


7. The user views real-time traffic waveforms and 3D topology animations on the GUI.

---

### Part 2: ASCII Architecture Diagram

```ascii
+-----------------------------------------------------------------------------------+
|                                  USER INTERFACE (GUI)                             |
|  [Web Platform: 2D/3D Topology Visualization, Real-time Waveforms]                |
+------------------------------------+----------------------------------------------+
                                     ^
                                     | (API Gateway / Direct Query)
                                     v
+-------------------+    +--------------------------+    +--------------------------+
| EXTERNAL STORAGE  |    |    SIMULATION            |    | KUBERNETES API           |
| [PostgreSQL/MySQL]|<-->|    CONTROLLER ("Brain")  |<-->| SERVER                   |
| (Topology Metadata)|    | [Parses YAML, Schedules, |    | (Resource Creation)      |
+-------------------+    |  Calculates Policy]      |    +--------------------------+
| TIME-SERIES DB    |    +------------+-------------+
| [VictoriaMetrics] |<--+             ^
| (Metrics Data)    |   |             | gRPC (Bi-directional Stream: Policies, Events)
+-------------------+   |             |
                        |   +---------v---------------------------------------------+
                        |   |  KUBERNETES NODE (Physical Host)                      |
                        |   |                                                       |
Metric Scrape (HTTP)____|   |  +---------------------+    +----------------------+  |
                        |   |  | NODE AGENT          |    | KUBELET / CONTAINER  |  |
                        |   |  | ("Hands & Feet")    |    | RUNTIME              |  |
                        |   |  | [DaemonSet, hostNet]|    +----------------------+  |
                        |   |  +----------+----------+             |                |
                        |   |             |                        |                |
                        |   |  (BPF Map Management, Prog Load,     | Launches       |
                        |   |   Netns Entry)                       |                |
                        |   |             |                        v                |
+-----------------------+   |  +----------v----------+    +--------+-------------+  |
| LEGEND                |   |  | KERNEL SPACE        |    | POD (SIMULATION NODE)|  |
|                       |   |  | ("Muscle")          |    | [Network Namespace]  |  |
| --- Control Flow      |   |  |                     |    |                      |  |
| === Data Traffic Flow |   |  |   [BPF MAPS]        |<---|---(eth0 inside Pod)--|  |
| (...) Hook Point      |   |  |   (rate_map, peers) |    |          |           |  |
+-----------------------+   |  |          ^          |    |      (TC Egress)     |  |
                            |  |          | Lookup   |    | [handle_edt_upload]  |  |
                            |  |          |          |    +==========|===========+  |
                            |  | +--------v--------+ |               |              |
                            |  | | VETH PAIR (Host)|<================+              |
                            |  | +--------+--------+ |                              |
                            |  |          |          |                              |
                            |  |      (TC Egress)    |                              |
                            |  | [handle_edt_download]                              |
                            |  |          |          |                              |
                            |  | +--------v--------+ |                              |
 Physical Network  <========|==| PHYSICAL NIC(eth0)|<===============================+
 (To other nodes)           |  | +--------+--------+ |
                            |  |          ^          |
                            |  |        (XDP)        |
                            |  | [handle_xdp_ingress]|
                            |  +---------------------+
                            +-------------------------------------------------------+

```
