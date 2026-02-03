## Architectural Roles of the Simulation Controller

### 1. gRPC Server (Agent-Facing)

* **Responsibilities:** Maintains long-lived connections with hundreds or thousands of Agents; receives heartbeats and Pod events reported by Agents; pushes global whitelists and traffic control policies to the Agents.
* **Implementation:** Implements the `SimulationAgentServiceServer` interface based on the `api/v1/simulation.proto` definition.

### 2. K8s CRD Controller / Listener (K8s API-Facing)

* **Responsibilities:** Watches for the creation or modification of Custom Resources (CRDs, such as `NetworkTopology`); triggers K8s API calls to create the actual Pods/Deployments based on the topology definition; monitors global Pod status to maintain an up-to-date IP mapping table.
* **Implementation:** Utilizes the `client-go` Informer mechanism or the `controller-runtime` framework.

### 3. Backend API Server (User/UI-Facing)

* **Responsibilities:** Provides RESTful or GraphQL interfaces for the frontend UI to display topologies, issue simulation commands, and query historical data.
* **Implementation:** An HTTP Server (such as Gin or Echo), usually running within the same process as the gRPC Server (on a different port).

