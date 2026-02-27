# Design and Implementation of an eBPF-based Distributed Network Simulator

## Functional Points:

1. **Containerized Deployment:** When physical network nodes are simulated, they are distributively deployed across different containers.
2. **Flexible Scalability:** The simulator supports horizontal scaling (scale out) to accommodate various network sizes.
3. **User-Friendly Topology Definition:** Users can easily describe and define the network topology.
4. **Simulation Control Center:** Provides a Graphical User Interface (GUI) to display and configure network topologies and node information. Advanced features include the ability for the control center to display the individual perspective (local view) of each node.
5. **Universal Programmability:** Offers a general-purpose mode that allows users to conveniently edit and input algorithms or code to implement the logic for both the overall network and individual nodes.
6. **eBPF-based Telemetry:** Leverages eBPF to collect real-time status data from the simulated network.

## Key Challenges and Technical Points:

1. **Configurable Bandwidth:** Bandwidth between containers must be adjustable to simulate different network scenarios. This traffic control (shaping) is to be implemented using eBPF.
2. **Traffic Isolation:** Simulated communication between containers (or even physical hosts in certain scenarios) must maintain strict traffic isolation. Since containers may handle non-simulation business traffic simultaneously, eBPF hooks should be used to bifurcate traffic. For example, on a 1Gbps link, simulation traffic could be restricted to 10Mbps while other traffic is limited to 990Mbps.
3. **GUI Technology Stack:** Which technology stack offers the best visual performance? The solution needs to support diverse scenarios:
    * **Mobile Swarm Networks:** (e.g., UAV or robot dog swarms) where 3D visualization is likely essential.
    * **Industrial IoT (IIoT):** Support for the design and verification of Time-Sensitive Networking (TSN).
    * **Microservices:** Network design and performance validation.
    * **On-board/Robotic Networks:** Vehicular and robotic communication systems.


4. **Data Management:** How to handle real-time access and long-term storage? Determine the optimal database strategy, considering:
    * **Time-Series Databases (TSDB):** For high-frequency metrics.
    * **Relational Databases (RDBMS):** For structured configuration and metadata.
    * **NoSQL/Non-structured Data Warehouses:** For flexible logs or large-scale trace data.
