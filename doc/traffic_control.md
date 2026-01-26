### 1. Core Concept: Identity & Lookup

This is the foundation. Every packet is checked against the eBPF Map.

```ascii
      +------------------------------------------+
      |          eBPF Map: PEERS_MAP             |
      +------------------------------------------+
      | Key: IP Address (Src or Dst)             |
      | Val: Peer Type                           |
      +--------------------+---------------------+
                           |
            +--------------+--------------+
            |                             |
    [ IP in Map? YES ]            [ IP in Map? NO ]
            |                             |
            v                             v
  +-------------------+         +-------------------+
  |    SIM TRAFFIC    |         |    SYS TRAFFIC    |
  |      (VIP)        |         |     (Common)      |
  +-------------------+         +-------------------+
  | No Delay          |         | High Bandwidth    |
  | Low Jitter        |         | Can be Delayed    |
  | Protected         |         | Can be Dropped    |
  +-------------------+         +-------------------+

```

---

### 2. Egress Flow (Pod -> World)

**Logic:** Classification & Shaping at Veth (Micro) -> Scheduling at Eth0 (Macro).

```ascii
[ POD / CONTAINER ]                                          [ HOST KERNEL / NIC ]
+----------------------------------------+                   +----------------------------------+
|                                        |                   |                                  |
|  App generates packet (skb)            |                   |                                  |
|             |                          |                   |                                  |
|  +----------v-----------------------+  |                   |                                  |
|  | Interface: eth0 (inside Pod)     |  |                   |                                  |
|  | TC Hook: handle_edt_upload       |  |                   |                                  |
|  +----------------------------------+  |                   |                                  |
|             |                          |                   |                                  |
|   1. LOOKUP (Dst IP)                   |                   |                                  |
|             |                          |                   |                                  |
|   +---------+----------+               |                   |                                  |
|   |                    |               |                   |                                  |
| [SIM]                [SYS]             |                   |                                  |
| Priority = 1         Priority = 0      |                   |                                  |
| Rate = 10Mbps        Rate = 990Mbps    |                   |                                  |
| bucket_sim           bucket_sys        |                   |                                  |
| tstamp = T           tstamp = T + 3ms  |                   |                                  |
|   |                    |               |                   |                                  |
|   +---------+----------+               |                   |                                  |
|             | (skb carries tstamp)     |                   |                                  |
|             |                          |                   |                                  |
|             v                          |                   |                                  |
|    (Leaves Container) ====================================>|  (Enters Host Stack)             |
|                                        |                   |            |                     |
+----------------------------------------+                   |            v                     |
                                                             |  +---------------------------+   |
                                                             |  | Interface: Host eth0      |   |
                                                             |  | TC Hook: handle_eth0_egress|  |
                                                             |  +---------------------------+   |
                                                             |            |                     |
                                                             |  1. READ skb->priority           |
                                                             |  2. IF Host Traffic (SSH):       |
                                                             |     Force T + 3ms                |
                                                             |                                  |
                                                             |  +---------------------------+   |
                                                             |  | Qdisc: FQ (Fair Queue)    |   |
                                                             |  +---------------------------+   |
                                                             |            |                     |
                                                             |      [ SCHEDULER ]               |
                                                             |            |                     |
                                                             |   [Time T]    [Time T+3ms]       |
                                                             |      |             |             |
                                                             |   [ SIM ]       [ SYS ]          |
                                                             |      |             |             |
                                                             +------+-------------+-------------+
                                                                    |             |
                                                                    v             v
                                                            =============================
                                                                  PHYSICAL WIRE

```

**Key Takeaway:** The `tstamp` is calculated inside the Pod (Veth). The FQ on the Host simply obeys this time. Sys traffic physically cannot leave the NIC until 3ms *after* Sim traffic would have.

---

### 3. Ingress Flow (World -> Host -> Pod)

**Logic:** XDP Protection (Defense) -> Veth Shaping (Input Control).

```ascii
       [ OUTSIDE WORLD ]
              |
              | (Incoming Packets)
              v
+----------------------------------------+
|          HOST PHYSICAL NIC             |
|                                        |
|  +----------------------------------+  |
|  | Interface: Host eth0             |  |
|  | XDP Hook: handle_xdp_ingress     |  |
|  +----------------------------------+  |
|             |                          |
|   1. LOOKUP (Src IP)                   |
|             |                          |
|   +---------+----------+               |
|   |                    |               |
| [SIM]                [SYS]             |
| XDP_PASS             Check Limit      <---- "The Bouncer"
| (Fast Path)          (e.g. 1Gbps)      |     (CPU Protection)
|   |                    |               |
|   |               Over Limit?          |
|   |              /           \         |
|   |           YES             NO       |
|   |            |              |        |
|   v         XDP_DROP          v        |
| (Into Kernel)               (Pass)     |
|   |                           |        |
+---+---------------------------+--------+
    |                           |
    | (Network Stack Routing)   |
    v                           v
+----------------------------------------+
|           HOST VETH SIDE               |
| (Interface peer to Pod's eth0)         |
|                                        |
|  +----------------------------------+  |
|  | TC Hook: handle_edt_download     |  |
|  +----------------------------------+  |
|             |                          |
|   1. LOOKUP (Src IP)                   |
|             |                          |
|   +---------+----------+               |
|   |                    |               |
| [SIM]                [SYS]             |
| Rate Limit           Rate Limit        |
| (Priority High)      (Priority Low)    |
|   |                    |               |
|   +---------+----------+               |
|             |                          |
|             v                          |
+-------------+--------------------------+
              |
              | (Enters Container Namespace)
              v
      [ POD / CONTAINER ]

```

**Key Takeaway:**

1. **XDP** runs *before* the OS allocates memory (skb), effectively saving the CPU from Sys/DDoS floods.
2. **TC (Download)** shapes the traffic just before it is "pushed" into the container, ensuring the app doesn't get overwhelmed.

### Summary of System Behavior

* **Sim Traffic:** "VIP Lane" -> No extra delays, bypasses policing, strictly timed.
* **Sys Traffic:** "Economy Lane" -> Has bandwidth but always yields (delayed), strictly policed at the door (XDP), dropped if noisy.
