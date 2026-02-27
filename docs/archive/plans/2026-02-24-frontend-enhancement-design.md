# Frontend Enhancement Design

**Date:** 2026-02-24
**Status:** Approved

## Overview

This document outlines the design for three frontend enhancements:
1. **P1:** Traffic Control frontend-backend integration
2. **P2:** Metrics Grafana integration
3. **P3:** Topology low-code creation mode

## Priority Order

| Priority | Feature | Effort | Reason |
|----------|---------|--------|--------|
| P1 | Traffic Control | Small | Backend complete, frontend API call only |
| P2 | Metrics Grafana | Medium | Dashboard config + frontend button |
| P3 | Topology Low-code | Large | UI redesign |

---

## P1: Traffic Control Frontend-Backend Integration

### Goal
Create independent TrafficControl management pages with form-based creation.

### Frontend Changes

#### 1. New Page: `TrafficControlCreate.tsx`
- Dropdown to select Topology (from NetworkTopology list)
- Dropdown to select Source NodeGroup (dynamic based on selected Topology)
- Dropdown to select Destination NodeGroup
- Policy form: Bandwidth / Latency / Jitter / Packet Loss
- Submit calls `apiClient.createTrafficControl()`

#### 2. New Page: `TrafficControlList.tsx`
- List all TrafficControls in current namespace
- Columns: Name, Source, Destination, Policy, Status
- Support Delete operation

#### 3. Route Configuration
- `/traffic-controls` - List page
- `/traffic-controls/create` - Create page

#### 4. Sidebar Menu
- Add "Traffic Controls" menu item

### Backend Changes
None required (already complete)

### Data Flow
```
User fills form → Frontend builds TrafficControl CRD → POST /api/v1/namespaces/{ns}/trafficcontrols
→ Controller creates CRD → Reconciler matches Pods → gRPC sends to Agent → BpfManager updates Map
```

### Files to Create/Modify
- `frontend/src/pages/TrafficControlCreate.tsx` (new)
- `frontend/src/pages/TrafficControlList.tsx` (new)
- `frontend/src/pages/TrafficControlCreate.css` (new)
- `frontend/src/pages/TrafficControlList.css` (new)
- `frontend/src/pages/index.ts` (modify)
- `frontend/src/App.tsx` (modify - add routes)
- `frontend/src/components/Layout/Sidebar.tsx` (modify - add menu item)

---

## P2: Metrics Grafana Integration

### Goal
Display key metrics overview in MetricsPage, provide button to open Grafana in new tab.

### Backend Changes

#### 1. Grafana Dashboard Provisioning
Add to `deploy/quick-monitor.yaml`:
- ConfigMap with Dashboard JSON (bandwidth, latency, packet loss panels)
- Dashboard auto-connects to Prometheus

#### 2. Anonymous Access Configuration
```yaml
env:
  - name: GF_AUTH_ANONYMOUS_ENABLED
    value: "true"
  - name: GF_AUTH_ANONYMOUS_ORG_ROLE
    value: "Viewer"
```

### Frontend Changes

#### 1. Simplify MetricsPage
- Keep SummaryCards (key metrics overview)
- Remove embedded Grafana iframe mode
- Add "Open Grafana" button (opens new tab)

#### 2. Grafana URL Configuration
- Read from environment variable `VITE_GRAFANA_URL`
- Default: `http://localhost:30092` (K8s NodePort)

### Data Flow
```
Agent exposes /metrics → Prometheus scrapes → Grafana queries → User views in Grafana
                          ↘ Frontend Prometheus API → MetricsPage overview
```

### Files to Create/Modify
- `deploy/quick-monitor.yaml` (modify - add Dashboard ConfigMap, Grafana env)
- `frontend/src/pages/MetricsPage.tsx` (modify - simplify, add button)
- `frontend/src/components/metrics/GrafanaLink.tsx` (new - optional component)
- `frontend/.env.local` (modify - add VITE_GRAFANA_URL)

---

## P3: Topology Low-Code Creation Mode

### Goal
Redesign TopologyCreate with visual canvas + config panel, YAML editor as toggle option.

### UI Layout

```
┌─────────────────────────────────────────────────────────────────┐
│  [← Back]  Create Topology                    [YAML] [Preview] │
├───────────────────────────────────────────┬─────────────────────┤
│                                           │                     │
│           Visual Canvas (React Flow)      │    Config Panel     │
│                                           │                     │
│   ┌─────┐      ┌─────┐                   │  Name: [________]   │
│   │leader│─────│follower│                │  Namespace: [_____] │
│   └─────┘      └─────┘                   │                     │
│       │                                   │  ── Node Groups ──  │
│       ▼                                   │  + Add Group        │
│   ┌─────┐                                │                     │
│   │gateway│                               │  ● leader (1)       │
│   └─────┘                                │    Image: [_____]   │
│                                           │    Replicas: [1]    │
│   [ + Add Node Group ]                    │    Labels: [...]    │
│                                           │                     │
│                                           │  ● follower (2)     │
│                                           │    Image: [_____]   │
│                                           │    Replicas: [2]    │
│                                           │                     │
│                                           │  [Create Topology]  │
└───────────────────────────────────────────┴─────────────────────┘
```

### Frontend Changes

#### 1. Refactor TopologyCreate.tsx
- Left side: React Flow canvas, nodes represent NodeGroups
- Right side: Config panel
  - Basic info: Name, Namespace
  - Node Groups list: click to select, edit details in panel
  - Add/Delete NodeGroup buttons
- Top toggle button: Visual mode / YAML mode

#### 2. Data Synchronization
- Visual → YAML: Real-time YAML preview generation
- YAML → Visual: Parse YAML, update canvas nodes
- Bidirectional binding

#### 3. Node Interaction
- Drag to add new NodeGroup
- Click node to select and edit in right panel
- Drag connection lines: NOT implemented (Traffic Control managed separately)

### Core Components

```typescript
// TopologyCreate.tsx structure
- VisualEditor (canvas + nodes)
- ConfigPanel (right-side config panel)
- YamlEditor (Monaco, shown in YAML mode)
- NodeGroupCard (node group card in config panel)
```

### Files to Create/Modify
- `frontend/src/pages/TopologyCreate.tsx` (major refactor)
- `frontend/src/pages/TopologyCreate.css` (major refactor)
- `frontend/src/components/topology/VisualEditor.tsx` (new)
- `frontend/src/components/topology/ConfigPanel.tsx` (new)
- `frontend/src/components/topology/NodeGroupCard.tsx` (new)

---

## Implementation Plan Summary

### Phase 1: Traffic Control (P1)
1. Create TrafficControlList page
2. Create TrafficControlCreate page
3. Add routes and sidebar menu
4. Test end-to-end: create TC → verify Pods get policy → verify eBPF map

### Phase 2: Metrics Grafana (P2)
1. Update quick-monitor.yaml with Dashboard ConfigMap
2. Configure Grafana anonymous access
3. Add "Open Grafana" button to MetricsPage
4. Test: deploy → verify Dashboard appears → verify frontend link

### Phase 3: Topology Low-Code (P3)
1. Create VisualEditor component
2. Create ConfigPanel component
3. Refactor TopologyCreate with dual-mode toggle
4. Test: create topology via visual mode → verify YAML output
