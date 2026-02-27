# Kuro Frontend Requirements

**Version:** 1.0  
**Date:** 2026-02-18  
**Status:** Validated

---

## Problem Statement

Distributed network simulation platform users (researchers/engineers) cannot intuitively understand node relationships and network status when configuring complex network topologies, leading to frequent configuration errors and long debugging cycles.

**Jobs-to-be-Done:**

> "When I design a 50-node drone swarm network simulation, I want to intuitively see each node's position and connections, so I can quickly discover topology errors and verify network parameter effects."

---

## Need Hierarchy

### Must Have (V1)

| ID | Need | Acceptance Criteria |
|----|------|---------------------|
| N-001 | View 2D topology | Given 50-node topology, when user opens topology page, all nodes and connections render within 3 seconds |
| N-002 | Real-time monitoring | When simulation is running, user sees bandwidth/latency/packet-loss metrics updating every second |
| N-003 | Parameter adjustment | When user modifies bandwidth to 10Mbps, eBPF policy takes effect within 3 seconds |
| N-004 | YAML upload | User can upload topology YAML file and see parsed topology visualization |
| N-005 | Status display | User sees node readiness count (e.g., "50/50 Nodes Ready") |

### Should Have (V2)

| ID | Need | Acceptance Criteria |
|----|------|---------------------|
| N-006 | 3D topology view | For drone swarm scenarios, nodes display in 3D space by physical coordinates |
| N-007 | Node local view | When user clicks a node and selects "local view", only that node's connections and traffic are shown |
| N-008 | Save/Load topology | User can save topology configuration and reload it later |

### Could Have (Future)

| ID | Need | Acceptance Criteria |
|----|------|---------------------|
| N-009 | Low-code editor | User can write node logic (Python/JS) in browser editor |
| N-010 | Report export | User can export simulation report as PDF/CSV |
| N-011 | History playback | User can replay historical simulation data |

---

## Constraint Inventory

### Real Constraints (Validated)

| Category | Constraint |
|----------|------------|
| Integration | Backend has REST API (:8080) and Prometheus metrics (:8080/metrics) |
| Data | VictoriaMetrics stores time-series data |
| Protocol | gRPC for agent communication, HTTP for user API |
| Scale | Support 100+ nodes in single simulation |

### Assumptions (To Validate)

| Assumption | Risk if Wrong |
|------------|---------------|
| Frontend team familiar with React | May need training or different framework |
| Browser can handle 100 nodes real-time updates | May need WebWorker or canvas optimization |
| Controller API is stable | May need API versioning |

---

## Scope Definition

### V1 Scope

```
INCLUDES:
  - 2D topology view (nodes + connections)
  - Real-time monitoring panel (bandwidth/latency/packet-loss charts)
  - Basic parameter adjustment (sliders for bandwidth, latency, packet loss)
  - YAML topology file upload and parsing
  - Topology status display (node count, running status)

EXCLUDES:
  - 3D view (deferred to V2)
  - Low-code editor (deferred until userProgram CRD is stable)
  - Node local view (deferred to V2)
  - History playback (deferred until storage strategy defined)
  - Report export (deferred)
  - User authentication (deferred)
```

### Deferred Items Trigger

| Deferred Item | Trigger for Reconsideration |
|---------------|----------------------------|
| 3D view | When drone swarm simulation is requested |
| Low-code editor | When userProgram CRD field is stable |
| History playback | When VictoriaMetrics storage strategy is defined |

---

## Technical Notes

### Data Sources

| Data | Source | Protocol |
|------|--------|----------|
| Topology structure | Controller API | HTTP GET /api/topologies |
| Node status | Controller API | HTTP GET /api/nodes |
| Real-time metrics | VictoriaMetrics | HTTP GET /api/v1/query_range |
| Policy updates | Controller API | HTTP PATCH /api/traffic-controls |

### Suggested Tech Stack (Not Requirement)

> These are suggestions, not requirements. The actual technology choice should be made during system design.

- **Framework:** React or Vue.js
- **2D Visualization:** React Flow or AntV X6
- **Charts:** ECharts or Recharts
- **State Management:** Zustand or Pinia
- **Build Tool:** Vite

---

## Handoff Checklist

- [x] Problem articulated without solution
- [x] Needs are testable and specific
- [x] Constraints inventoried (real vs. assumed)
- [x] Scope bounded with explicit V1 definition
- [x] Deferred items listed with triggers

**Next Step:** Hand off to system-design skill for architecture design.
