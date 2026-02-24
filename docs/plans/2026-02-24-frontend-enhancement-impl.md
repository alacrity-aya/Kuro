# Frontend Enhancement Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement three frontend enhancements: Traffic Control management, Metrics Grafana integration, and Topology low-code creation mode.

**Architecture:** 
- P1: New React pages for TrafficControl CRUD with API integration
- P2: Grafana Dashboard provisioning + frontend external link
- P3: Visual editor with React Flow canvas + config panel, YAML as toggle option

**Tech Stack:** React 18, TypeScript, React Flow, Zustand, Vite, Monaco Editor, Grafana, Prometheus

---

## Phase 1: Traffic Control Frontend-Backend Integration (P1)

### Task 1.1: Add Sidebar Menu Item

**Files:**
- Modify: `frontend/src/components/Layout/Sidebar.tsx`
- Modify: `frontend/src/App.tsx`

**Step 1: Add menu item to Sidebar**

In `frontend/src/components/Layout/Sidebar.tsx`, the menu items are passed as props from App.tsx. Check the current menuItems array in App.tsx:

```typescript
// In App.tsx, find menuItems array and add:
const menuItems: MenuItem[] = [
  { id: 'dashboard', label: 'Dashboard', icon: 'dashboard' },
  { id: 'topologies', label: 'Topologies', icon: 'topology' },
  { id: 'traffic-controls', label: 'Traffic Controls', icon: 'node' },
  { id: 'metrics', label: 'Metrics', icon: 'metrics' },
];
```

**Step 2: Add route handler in App.tsx**

In `frontend/src/App.tsx`, add case for traffic-controls:

```typescript
// In handleMenuItemClick function, add case:
case 'traffic-controls':
  navigate('/traffic-controls');
  break;
```

**Step 3: Verify menu item appears**

Run: `cd frontend && npm run dev`
Navigate to: `http://localhost:5173`
Expected: "Traffic Controls" menu item appears in sidebar

**Step 4: Commit**

```bash
git add frontend/src/App.tsx
git commit -m "feat(frontend): add Traffic Controls menu item"
```

---

### Task 1.2: Create TrafficControlList Page

**Files:**
- Create: `frontend/src/pages/TrafficControlList.tsx`
- Create: `frontend/src/pages/TrafficControlList.css`
- Modify: `frontend/src/pages/index.ts`
- Modify: `frontend/src/App.tsx`

**Step 1: Create TrafficControlList.tsx**

```tsx
import { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import type { TrafficControl } from '../types/api';
import { apiClient } from '../api/client';
import './TrafficControlList.css';

export default function TrafficControlList() {
  const navigate = useNavigate();
  const [trafficControls, setTrafficControls] = useState<TrafficControl[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchTrafficControls = useCallback(async () => {
    setLoading(true);
    try {
      const response = await apiClient.listTrafficControls('kuro-experiment');
      if (response.success && response.data) {
        setTrafficControls(response.data.items);
      } else {
        setError(response.error || 'Failed to fetch traffic controls');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchTrafficControls();
  }, [fetchTrafficControls]);

  const handleDelete = async (name: string) => {
    if (!confirm(`Delete traffic control "${name}"?`)) return;
    
    const response = await apiClient.deleteTrafficControl(name, 'kuro-experiment');
    if (response.success) {
      setTrafficControls(prev => prev.filter(tc => tc.metadata.name !== name));
    } else {
      alert(response.error || 'Failed to delete');
    }
  };

  const handleCreate = () => {
    navigate('/traffic-controls/create');
  };

  if (loading) {
    return <div className="tc-list-loading">Loading traffic controls...</div>;
  }

  if (error) {
    return <div className="tc-list-error">Error: {error}</div>;
  }

  return (
    <div className="tc-list">
      <div className="tc-list__header">
        <h1>Traffic Controls</h1>
        <button className="tc-list__create-btn" onClick={handleCreate}>
          + Create Traffic Control
        </button>
      </div>

      <div className="tc-list__content">
        {trafficControls.length === 0 ? (
          <div className="tc-list__empty">
            No traffic controls found. Create one to get started.
          </div>
        ) : (
          <div className="tc-list__grid">
            {trafficControls.map(tc => (
              <div key={tc.metadata.uid} className="tc-card">
                <div className="tc-card__header">
                  <h3 className="tc-card__name">{tc.metadata.name}</h3>
                  <span className={`tc-card__phase tc-card__phase--${(tc.status?.phase || 'Unknown').toLowerCase()}`}>
                    {tc.status?.phase || 'Unknown'}
                  </span>
                </div>
                <div className="tc-card__body">
                  <div className="tc-card__row">
                    <span className="tc-card__label">Source:</span>
                    <span className="tc-card__value">{JSON.stringify(tc.spec.source.matchLabels)}</span>
                  </div>
                  <div className="tc-card__row">
                    <span className="tc-card__label">Destination:</span>
                    <span className="tc-card__value">{JSON.stringify(tc.spec.destination.matchLabels)}</span>
                  </div>
                  <div className="tc-card__row">
                    <span className="tc-card__label">Policy:</span>
                    <span className="tc-card__value">
                      {tc.spec.policy.bandwidth} | {tc.spec.policy.latency}
                    </span>
                  </div>
                </div>
                <div className="tc-card__actions">
                  <button 
                    className="tc-card__btn tc-card__btn--danger"
                    onClick={() => handleDelete(tc.metadata.name)}
                  >
                    Delete
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
```

**Step 2: Create TrafficControlList.css**

```css
.tc-list {
  padding: 24px;
  height: 100%;
  overflow-y: auto;
}

.tc-list__header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
}

.tc-list__header h1 {
  margin: 0;
  font-size: 24px;
  color: #1e293b;
}

.tc-list__create-btn {
  padding: 10px 20px;
  background: #3b82f6;
  color: white;
  border: none;
  border-radius: 8px;
  font-size: 14px;
  cursor: pointer;
}

.tc-list__create-btn:hover {
  background: #2563eb;
}

.tc-list__empty {
  text-align: center;
  padding: 48px;
  color: #64748b;
}

.tc-list__grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
  gap: 16px;
}

.tc-card {
  background: white;
  border-radius: 12px;
  border: 1px solid #e2e8f0;
  overflow: hidden;
}

.tc-card__header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px;
  border-bottom: 1px solid #e2e8f0;
}

.tc-card__name {
  margin: 0;
  font-size: 16px;
  font-weight: 600;
}

.tc-card__phase {
  padding: 4px 10px;
  border-radius: 12px;
  font-size: 12px;
  text-transform: uppercase;
}

.tc-card__phase--active { background: #dcfce7; color: #16a34a; }
.tc-card__phase--pending { background: #fef3c7; color: #d97706; }
.tc-card__phase--partial { background: #dbeafe; color: #2563eb; }
.tc-card__phase--failed { background: #fee2e2; color: #dc2626; }
.tc-card__phase--unknown { background: #f1f5f9; color: #64748b; }

.tc-card__body {
  padding: 16px;
}

.tc-card__row {
  display: flex;
  margin-bottom: 8px;
}

.tc-card__label {
  width: 100px;
  color: #64748b;
  font-size: 13px;
}

.tc-card__value {
  flex: 1;
  font-size: 13px;
  color: #1e293b;
}

.tc-card__actions {
  padding: 12px 16px;
  border-top: 1px solid #e2e8f0;
  display: flex;
  justify-content: flex-end;
  gap: 8px;
}

.tc-card__btn {
  padding: 6px 12px;
  border: none;
  border-radius: 6px;
  font-size: 13px;
  cursor: pointer;
}

.tc-card__btn--danger {
  background: #fee2e2;
  color: #dc2626;
}

.tc-card__btn--danger:hover {
  background: #fecaca;
}
```

**Step 3: Export from index.ts**

In `frontend/src/pages/index.ts`:

```typescript
export { default as TrafficControlList } from './TrafficControlList';
export { default as TrafficControlCreate } from './TrafficControlCreate';
```

**Step 4: Add route in App.tsx**

In `frontend/src/App.tsx`, add Route inside Routes:

```tsx
<Route path="/traffic-controls" element={<TrafficControlList onCreateTrafficControl={handleCreateTrafficControl} />} />
```

Add handler function:

```typescript
const handleCreateTrafficControl = () => {
  navigate('/traffic-controls/create');
};
```

Import the component:

```typescript
import { Dashboard, TopologyList, TopologyDetail, TopologyCreate, MetricsPage, TrafficControlList } from './pages';
```

**Step 5: Verify list page works**

Run: `cd frontend && npm run dev`
Navigate to: `http://localhost:5173/traffic-controls`
Expected: TrafficControlList page displays (may be empty if no TCs exist)

**Step 6: Commit**

```bash
git add frontend/src/pages/TrafficControlList.tsx frontend/src/pages/TrafficControlList.css frontend/src/pages/index.ts frontend/src/App.tsx
git commit -m "feat(frontend): add TrafficControlList page"
```

---

### Task 1.3: Create TrafficControlCreate Page

**Files:**
- Create: `frontend/src/pages/TrafficControlCreate.tsx`
- Create: `frontend/src/pages/TrafficControlCreate.css`
- Modify: `frontend/src/App.tsx`

**Step 1: Create TrafficControlCreate.tsx**

```tsx
import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import type { NetworkTopology, TrafficControl, NodeGroup } from '../types/api';
import { apiClient } from '../api/client';
import './TrafficControlCreate.css';

interface TrafficControlCreateProps {
  onCreated?: (name: string, namespace: string) => void;
  onCancel?: () => void;
}

export default function TrafficControlCreate({ onCreated, onCancel }: TrafficControlCreateProps) {
  const navigate = useNavigate();
  
  // Form state
  const [name, setName] = useState('');
  const [selectedTopology, setSelectedTopology] = useState<string>('');
  const [sourceGroup, setSourceGroup] = useState<string>('');
  const [destGroup, setDestGroup] = useState<string>('');
  
  // Policy state
  const [bandwidth, setBandwidth] = useState('10Mbps');
  const [latency, setLatency] = useState('10ms');
  const [jitter, setJitter] = useState('5ms');
  const [packetLoss, setPacketLoss] = useState('0.1');
  
  // Data state
  const [topologies, setTopologies] = useState<NetworkTopology[]>([]);
  const [nodeGroups, setNodeGroups] = useState<NodeGroup[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Fetch topologies on mount
  useEffect(() => {
    async function fetchTopologies() {
      const response = await apiClient.listTopologies('kuro-experiment');
      if (response.success && response.data) {
        setTopologies(response.data.items);
      }
    }
    fetchTopologies();
  }, []);

  // Update node groups when topology selected
  useEffect(() => {
    if (!selectedTopology) {
      setNodeGroups([]);
      return;
    }
    
    const topology = topologies.find(t => t.metadata.name === selectedTopology);
    if (topology?.spec?.nodeGroups) {
      setNodeGroups(topology.spec.nodeGroups);
    }
  }, [selectedTopology, topologies]);

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!name || !selectedTopology || !sourceGroup || !destGroup) {
      setError('Please fill in all required fields');
      return;
    }

    setLoading(true);
    setError(null);

    // Find the topology to get labels for source/destination groups
    const topology = topologies.find(t => t.metadata.name === selectedTopology);
    const srcGroup = nodeGroups.find(g => g.name === sourceGroup);
    const dstGroup = nodeGroups.find(g => g.name === destGroup);

    if (!topology || !srcGroup || !dstGroup) {
      setError('Invalid topology or node group selection');
      setLoading(false);
      return;
    }

    const tc: TrafficControl = {
      apiVersion: 'simulation.kuro.io/v1alpha1',
      kind: 'TrafficControl',
      metadata: {
        name,
        namespace: 'kuro-experiment',
      },
      spec: {
        source: {
          matchLabels: srcGroup.labels || { 'kuro.io/node-group': srcGroup.name },
        },
        destination: {
          matchLabels: dstGroup.labels || { 'kuro.io/node-group': dstGroup.name },
        },
        policy: {
          bandwidth,
          latency,
          jitter,
          packetLoss: `${packetLoss}%`,
        },
      },
    };

    try {
      const response = await apiClient.createTrafficControl(tc);
      if (response.success) {
        if (onCreated) {
          onCreated(name, 'kuro-experiment');
        } else {
          navigate('/traffic-controls');
        }
      } else {
        setError(response.error || 'Failed to create traffic control');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  }, [name, selectedTopology, sourceGroup, destGroup, bandwidth, latency, jitter, packetLoss, topologies, nodeGroups, onCreated, navigate]);

  const handleCancel = () => {
    if (onCancel) {
      onCancel();
    } else {
      navigate('/traffic-controls');
    }
  };

  return (
    <div className="tc-create">
      <div className="tc-create__header">
        <h1>Create Traffic Control</h1>
      </div>

      <form className="tc-create__form" onSubmit={handleSubmit}>
        {error && <div className="tc-create__error">{error}</div>}

        <div className="tc-create__section">
          <h2>Basic Info</h2>
          
          <div className="tc-create__field">
            <label>Name *</label>
            <input
              type="text"
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="my-traffic-control"
              required
            />
          </div>

          <div className="tc-create__field">
            <label>Topology *</label>
            <select
              value={selectedTopology}
              onChange={e => {
                setSelectedTopology(e.target.value);
                setSourceGroup('');
                setDestGroup('');
              }}
              required
            >
              <option value="">Select a topology...</option>
              {topologies.map(t => (
                <option key={t.metadata.name} value={t.metadata.name}>
                  {t.metadata.name}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="tc-create__section">
          <h2>Source & Destination</h2>
          
          <div className="tc-create__field">
            <label>Source NodeGroup *</label>
            <select
              value={sourceGroup}
              onChange={e => setSourceGroup(e.target.value)}
              disabled={!selectedTopology}
              required
            >
              <option value="">Select source...</option>
              {nodeGroups.map(g => (
                <option key={g.name} value={g.name}>
                  {g.name} ({g.replicas} replicas)
                </option>
              ))}
            </select>
          </div>

          <div className="tc-create__field">
            <label>Destination NodeGroup *</label>
            <select
              value={destGroup}
              onChange={e => setDestGroup(e.target.value)}
              disabled={!selectedTopology}
              required
            >
              <option value="">Select destination...</option>
              {nodeGroups.map(g => (
                <option key={g.name} value={g.name}>
                  {g.name} ({g.replicas} replicas)
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="tc-create__section">
          <h2>Traffic Policy</h2>
          
          <div className="tc-create__field">
            <label>Bandwidth</label>
            <input
              type="text"
              value={bandwidth}
              onChange={e => setBandwidth(e.target.value)}
              placeholder="10Mbps"
            />
          </div>

          <div className="tc-create__field">
            <label>Latency</label>
            <input
              type="text"
              value={latency}
              onChange={e => setLatency(e.target.value)}
              placeholder="10ms"
            />
          </div>

          <div className="tc-create__field">
            <label>Jitter</label>
            <input
              type="text"
              value={jitter}
              onChange={e => setJitter(e.target.value)}
              placeholder="5ms"
            />
          </div>

          <div className="tc-create__field">
            <label>Packet Loss (%)</label>
            <input
              type="number"
              step="0.1"
              min="0"
              max="100"
              value={packetLoss}
              onChange={e => setPacketLoss(e.target.value)}
              placeholder="0.1"
            />
          </div>
        </div>

        <div className="tc-create__actions">
          <button type="button" className="tc-create__btn tc-create__btn--secondary" onClick={handleCancel}>
            Cancel
          </button>
          <button type="submit" className="tc-create__btn tc-create__btn--primary" disabled={loading}>
            {loading ? 'Creating...' : 'Create Traffic Control'}
          </button>
        </div>
      </form>
    </div>
  );
}
```

**Step 2: Create TrafficControlCreate.css**

```css
.tc-create {
  padding: 24px;
  max-width: 800px;
  margin: 0 auto;
}

.tc-create__header {
  margin-bottom: 24px;
}

.tc-create__header h1 {
  margin: 0;
  font-size: 24px;
  color: #1e293b;
}

.tc-create__form {
  background: white;
  border-radius: 12px;
  border: 1px solid #e2e8f0;
  padding: 24px;
}

.tc-create__error {
  background: #fee2e2;
  color: #dc2626;
  padding: 12px;
  border-radius: 8px;
  margin-bottom: 16px;
}

.tc-create__section {
  margin-bottom: 24px;
}

.tc-create__section h2 {
  margin: 0 0 16px 0;
  font-size: 16px;
  font-weight: 600;
  color: #334155;
  border-bottom: 1px solid #e2e8f0;
  padding-bottom: 8px;
}

.tc-create__field {
  margin-bottom: 16px;
}

.tc-create__field label {
  display: block;
  margin-bottom: 6px;
  font-size: 14px;
  font-weight: 500;
  color: #475569;
}

.tc-create__field input,
.tc-create__field select {
  width: 100%;
  padding: 10px 12px;
  border: 1px solid #d1d5db;
  border-radius: 8px;
  font-size: 14px;
}

.tc-create__field input:focus,
.tc-create__field select:focus {
  outline: none;
  border-color: #3b82f6;
  box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
}

.tc-create__field select:disabled {
  background: #f1f5f9;
  cursor: not-allowed;
}

.tc-create__actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 24px;
  padding-top: 16px;
  border-top: 1px solid #e2e8f0;
}

.tc-create__btn {
  padding: 10px 20px;
  border-radius: 8px;
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
}

.tc-create__btn--primary {
  background: #3b82f6;
  color: white;
  border: none;
}

.tc-create__btn--primary:hover:not(:disabled) {
  background: #2563eb;
}

.tc-create__btn--primary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.tc-create__btn--secondary {
  background: white;
  color: #475569;
  border: 1px solid #d1d5db;
}

.tc-create__btn--secondary:hover {
  background: #f9fafb;
}
```

**Step 3: Add route in App.tsx**

Add import:
```typescript
import { TrafficControlCreate } from './pages';
```

Add Route:
```tsx
<Route 
  path="/traffic-controls/create" 
  element={<TrafficControlCreate onCreated={() => navigate('/traffic-controls')} onCancel={() => navigate('/traffic-controls')} />} 
/>
```

**Step 4: Verify create page works**

Run: `cd frontend && npm run dev`
Navigate to: `http://localhost:5173/traffic-controls/create`
Expected: Form displays with Topology dropdown populated

**Step 5: Commit**

```bash
git add frontend/src/pages/TrafficControlCreate.tsx frontend/src/pages/TrafficControlCreate.css frontend/src/App.tsx
git commit -m "feat(frontend): add TrafficControlCreate page"
```

---

### Task 1.4: End-to-End Test Traffic Control

**Prerequisites:**
- Kind cluster running with controller and agent
- A NetworkTopology created (e.g., test-visibility)

**Step 1: Verify API endpoint exists**

Run: `kubectl port-forward -n kuro-system svc/controller 8080:8080 &`

Test API:
```bash
curl http://localhost:8080/api/v1/namespaces/kuro-experiment/trafficcontrols
```
Expected: JSON response with items array

**Step 2: Create TrafficControl via frontend**

1. Navigate to `http://localhost:5173/traffic-controls/create`
2. Fill form:
   - Name: `test-tc`
   - Topology: select existing topology
   - Source: select node group A
   - Destination: select node group B
   - Bandwidth: `10Mbps`
   - Latency: `20ms`
3. Click "Create Traffic Control"
4. Expected: Redirects to list page, new TC appears

**Step 3: Verify CRD created in K8s**

```bash
kubectl get trafficcontrol -n kuro-experiment
kubectl describe trafficcontrol test-tc -n kuro-experiment
```
Expected: TrafficControl resource exists with correct spec

**Step 4: Verify controller logs**

```bash
kubectl logs -n kuro-system deployment/controller | grep -i traffic
```
Expected: Logs showing TrafficControl reconciliation

**Step 5: Delete TrafficControl**

1. Click Delete button on the card
2. Confirm deletion
3. Expected: Card removed from list

```bash
kubectl get trafficcontrol -n kuro-experiment
```
Expected: No traffic controls (or test-tc removed)

**Step 6: Commit (if any fixes needed)**

```bash
git add -A
git commit -m "fix(frontend): traffic control integration fixes"
```

---

## Phase 2: Metrics Grafana Integration (P2)

### Task 2.1: Update quick-monitor.yaml with Dashboard

**Files:**
- Modify: `deploy/quick-monitor.yaml`

**Step 1: Add Dashboard ConfigMap**

Add after the Prometheus ConfigMap:

```yaml
---
# ==============================================================================
# 6. Grafana Dashboard ConfigMap
# ==============================================================================
apiVersion: v1
kind: ConfigMap
metadata:
  name: grafana-dashboards
  namespace: kuro-monitor
  labels:
    grafana_dashboard: "1"
data:
  kuro-dashboard.json: |
    {
      "dashboard": {
        "title": "Kuro Network Metrics",
        "uid": "kuro-dashboard",
        "editable": true,
        "panels": [
          {
            "title": "Bandwidth (Sim Traffic)",
            "type": "timeseries",
            "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0},
            "targets": [
              {
                "expr": "rate(kuro_pod_bytes_total{traffic_type=\"sim\"}[5m]) * 8 / 1000000",
                "legendFormat": "{{pod}} - {{direction}}",
                "refId": "A"
              }
            ],
            "fieldConfig": {
              "defaults": {
                "unit": "Mbps"
              }
            }
          },
          {
            "title": "Latency Distribution",
            "type": "heatmap",
            "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0},
            "targets": [
              {
                "expr": "rate(kuro_pod_latency_seconds_bucket[5m])",
                "legendFormat": "{{le}}",
                "refId": "A",
                "format": "heatmap"
              }
            ]
          },
          {
            "title": "Packet Drop Rate",
            "type": "timeseries",
            "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8},
            "targets": [
              {
                "expr": "rate(kuro_pod_drops_total[5m])",
                "legendFormat": "{{pod}}",
                "refId": "A"
              }
            ]
          },
          {
            "title": "Active Pods",
            "type": "stat",
            "gridPos": {"h": 4, "w": 6, "x": 12, "y": 8},
            "targets": [
              {
                "expr": "count(up{job=\"kuro-agents\"})",
                "refId": "A"
              }
            ]
          }
        ]
      }
    }
```

**Step 2: Update Grafana Deployment for anonymous access and dashboard provisioning**

Replace the Grafana Deployment section:

```yaml
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: grafana
  namespace: kuro-monitor
spec:
  replicas: 1
  selector:
    matchLabels:
      app: grafana
  template:
    metadata:
      labels:
        app: grafana
    spec:
      containers:
        - name: grafana
          image: grafana/grafana:latest
          ports:
            - containerPort: 3000
          env:
            - name: GF_SECURITY_ADMIN_PASSWORD
              value: "admin"
            - name: GF_AUTH_ANONYMOUS_ENABLED
              value: "true"
            - name: GF_AUTH_ANONYMOUS_ORG_ROLE
              value: "Viewer"
            - name: GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH
              value: /var/lib/grafana/dashboards/kuro-dashboard.json
          volumeMounts:
            - name: dashboard-volume
              mountPath: /var/lib/grafana/dashboards
      volumes:
        - name: dashboard-volume
          configMap:
            name: grafana-dashboards
```

**Step 3: Deploy and verify**

```bash
kubectl apply -f deploy/quick-monitor.yaml
kubectl rollout restart deployment/grafana -n kuro-monitor
```

**Step 4: Verify Dashboard**

```bash
kubectl port-forward -n kuro-monitor svc/grafana 3000:3000 &
```

Open: `http://localhost:3000`
Expected: Grafana loads with "Kuro Network Metrics" dashboard

**Step 5: Commit**

```bash
git add deploy/quick-monitor.yaml
git commit -m "feat(monitor): add Grafana dashboard with anonymous access"
```

---

### Task 2.2: Add Grafana Link to MetricsPage

**Files:**
- Modify: `frontend/.env.local`
- Modify: `frontend/src/pages/MetricsPage.tsx`

**Step 1: Add environment variable**

In `frontend/.env.local`:

```
VITE_GRAFANA_URL=http://localhost:30092
```

**Step 2: Add Grafana link button to MetricsPage**

In `frontend/src/pages/MetricsPage.tsx`, find the header section and add:

```tsx
// Add at top of file
const GRAFANA_URL = import.meta.env.VITE_GRAFANA_URL || 'http://localhost:30092';

// In the header controls section, add:
<div className="metrics-page__control-group">
  <a
    href={GRAFANA_URL}
    target="_blank"
    rel="noopener noreferrer"
    className="metrics-page__grafana-btn"
  >
    Open Grafana
  </a>
</div>
```

**Step 3: Add CSS for the button**

In `frontend/src/pages/MetricsPage.css`:

```css
.metrics-page__grafana-btn {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 8px 16px;
  background: #f97316;
  color: white;
  text-decoration: none;
  border-radius: 6px;
  font-size: 14px;
  font-weight: 500;
}

.metrics-page__grafana-btn:hover {
  background: #ea580c;
}
```

**Step 4: Remove GrafanaEmbed mode (optional cleanup)**

Remove the viewMode state and GrafanaEmbed component usage. Keep only the Charts view with the external link button.

**Step 5: Verify**

Run: `cd frontend && npm run dev`
Navigate to: `http://localhost:5173/metrics`
Expected: "Open Grafana" button appears, clicking opens new tab with Grafana

**Step 6: Commit**

```bash
git add frontend/.env.local frontend/src/pages/MetricsPage.tsx frontend/src/pages/MetricsPage.css
git commit -m "feat(frontend): add Grafana external link to MetricsPage"
```

---

### Task 2.3: End-to-End Test Grafana Integration

**Step 1: Ensure monitoring stack is running**

```bash
kubectl get pods -n kuro-monitor
kubectl get pods -n kuro-system
```
Expected: prometheus and grafana pods running, kuro-agent pods running

**Step 2: Create test topology and generate traffic**

```bash
kubectl apply -f deploy/test-topology.yaml
```

Wait for pods to be ready, then exec into one pod and generate traffic:

```bash
kubectl exec -it -n kuro-experiment <pod-name> -- ping <another-pod-ip>
```

**Step 3: Verify metrics in Prometheus**

```bash
kubectl port-forward -n kuro-monitor svc/prometheus 9090:9090 &
```

Open: `http://localhost:9090`
Query: `kuro_pod_bytes_total`
Expected: Metrics appear

**Step 4: Verify Dashboard in Grafana**

```bash
kubectl port-forward -n kuro-monitor svc/grafana 3000:3000 &
```

Open: `http://localhost:3000`
Navigate to: Dashboards → Kuro Network Metrics
Expected: Dashboard shows bandwidth/latency charts

**Step 5: Verify frontend link**

Navigate to: `http://localhost:5173/metrics`
Click: "Open Grafana" button
Expected: New tab opens with Grafana

**Step 6: Commit (if any fixes)**

```bash
git add -A
git commit -m "fix(monitor): grafana integration fixes"
```

---

## Phase 3: Topology Low-Code Creation Mode (P3)

### Task 3.1: Create ConfigPanel Component

**Files:**
- Create: `frontend/src/components/topology/ConfigPanel.tsx`
- Create: `frontend/src/components/topology/ConfigPanel.css`

**Step 1: Create ConfigPanel.tsx**

```tsx
import { useState } from 'react';
import type { NodeGroup } from '../../types/api';
import './ConfigPanel.css';

interface ConfigPanelProps {
  name: string;
  namespace: string;
  nodeGroups: NodeGroup[];
  selectedGroupId: string | null;
  onNameChange: (name: string) => void;
  onNamespaceChange: (namespace: string) => void;
  onAddGroup: () => void;
  onSelectGroup: (groupId: string) => void;
  onDeleteGroup: (groupId: string) => void;
  onUpdateGroup: (groupId: string, updates: Partial<NodeGroup>) => void;
  onSubmit: () => void;
  submitLabel?: string;
  isSubmitting?: boolean;
}

export default function ConfigPanel({
  name,
  namespace,
  nodeGroups,
  selectedGroupId,
  onNameChange,
  onNamespaceChange,
  onAddGroup,
  onSelectGroup,
  onDeleteGroup,
  onUpdateGroup,
  onSubmit,
  submitLabel = 'Create Topology',
  isSubmitting = false,
}: ConfigPanelProps) {
  const selectedGroup = nodeGroups.find(g => g.name === selectedGroupId);

  return (
    <div className="config-panel">
      <div className="config-panel__section">
        <h3>Basic Info</h3>
        
        <div className="config-panel__field">
          <label>Name</label>
          <input
            type="text"
            value={name}
            onChange={e => onNameChange(e.target.value)}
            placeholder="my-topology"
          />
        </div>

        <div className="config-panel__field">
          <label>Namespace</label>
          <input
            type="text"
            value={namespace}
            onChange={e => onNamespaceChange(e.target.value)}
            placeholder="kuro-experiment"
          />
        </div>
      </div>

      <div className="config-panel__section">
        <div className="config-panel__section-header">
          <h3>Node Groups</h3>
          <button className="config-panel__add-btn" onClick={onAddGroup}>
            + Add
          </button>
        </div>

        <div className="config-panel__groups">
          {nodeGroups.map(group => (
            <div
              key={group.name}
              className={`config-panel__group ${selectedGroupId === group.name ? 'config-panel__group--selected' : ''}`}
              onClick={() => onSelectGroup(group.name)}
            >
              <div className="config-panel__group-header">
                <span className="config-panel__group-name">{group.name}</span>
                <span className="config-panel__group-replicas">{group.replicas}x</span>
                <button
                  className="config-panel__group-delete"
                  onClick={e => {
                    e.stopPropagation();
                    onDeleteGroup(group.name);
                  }}
                >
                  ×
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {selectedGroup && (
        <div className="config-panel__section">
          <h3>Edit: {selectedGroup.name}</h3>
          
          <div className="config-panel__field">
            <label>Name</label>
            <input
              type="text"
              value={selectedGroup.name}
              onChange={e => onUpdateGroup(selectedGroup.name, { name: e.target.value })}
            />
          </div>

          <div className="config-panel__field">
            <label>Replicas</label>
            <input
              type="number"
              min="1"
              value={selectedGroup.replicas || 1}
              onChange={e => onUpdateGroup(selectedGroup.name, { replicas: parseInt(e.target.value) || 1 })}
            />
          </div>

          <div className="config-panel__field">
            <label>Image</label>
            <input
              type="text"
              value={selectedGroup.image || ''}
              onChange={e => onUpdateGroup(selectedGroup.name, { image: e.target.value })}
              placeholder="busybox:latest"
            />
          </div>

          <div className="config-panel__field">
            <label>Role Label</label>
            <input
              type="text"
              value={selectedGroup.labels?.role || ''}
              onChange={e => onUpdateGroup(selectedGroup.name, {
                labels: { ...selectedGroup.labels, role: e.target.value }
              })}
              placeholder="leader"
            />
          </div>
        </div>
      )}

      <div className="config-panel__actions">
        <button
          className="config-panel__submit"
          onClick={onSubmit}
          disabled={isSubmitting || !name || nodeGroups.length === 0}
        >
          {isSubmitting ? 'Creating...' : submitLabel}
        </button>
      </div>
    </div>
  );
}
```

**Step 2: Create ConfigPanel.css**

```css
.config-panel {
  width: 320px;
  background: white;
  border-left: 1px solid #e2e8f0;
  display: flex;
  flex-direction: column;
  overflow-y: auto;
}

.config-panel__section {
  padding: 16px;
  border-bottom: 1px solid #e2e8f0;
}

.config-panel__section h3 {
  margin: 0 0 12px 0;
  font-size: 14px;
  font-weight: 600;
  color: #334155;
}

.config-panel__section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}

.config-panel__section-header h3 {
  margin: 0;
}

.config-panel__add-btn {
  padding: 4px 12px;
  background: #3b82f6;
  color: white;
  border: none;
  border-radius: 4px;
  font-size: 12px;
  cursor: pointer;
}

.config-panel__field {
  margin-bottom: 12px;
}

.config-panel__field label {
  display: block;
  margin-bottom: 4px;
  font-size: 12px;
  color: #64748b;
}

.config-panel__field input {
  width: 100%;
  padding: 8px;
  border: 1px solid #d1d5db;
  border-radius: 6px;
  font-size: 13px;
}

.config-panel__field input:focus {
  outline: none;
  border-color: #3b82f6;
}

.config-panel__groups {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.config-panel__group {
  display: flex;
  align-items: center;
  padding: 8px 12px;
  background: #f8fafc;
  border: 1px solid #e2e8f0;
  border-radius: 6px;
  cursor: pointer;
}

.config-panel__group:hover {
  background: #f1f5f9;
}

.config-panel__group--selected {
  background: #dbeafe;
  border-color: #3b82f6;
}

.config-panel__group-header {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 100%;
}

.config-panel__group-name {
  flex: 1;
  font-size: 13px;
  font-weight: 500;
}

.config-panel__group-replicas {
  font-size: 12px;
  color: #64748b;
}

.config-panel__group-delete {
  width: 20px;
  height: 20px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: transparent;
  border: none;
  color: #94a3b8;
  cursor: pointer;
  font-size: 16px;
}

.config-panel__group-delete:hover {
  color: #ef4444;
}

.config-panel__actions {
  padding: 16px;
  margin-top: auto;
}

.config-panel__submit {
  width: 100%;
  padding: 12px;
  background: #3b82f6;
  color: white;
  border: none;
  border-radius: 8px;
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
}

.config-panel__submit:hover:not(:disabled) {
  background: #2563eb;
}

.config-panel__submit:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
```

**Step 3: Verify component compiles**

Run: `cd frontend && npm run build`
Expected: No compilation errors

**Step 4: Commit**

```bash
git add frontend/src/components/topology/ConfigPanel.tsx frontend/src/components/topology/ConfigPanel.css
git commit -m "feat(frontend): add ConfigPanel component for low-code topology"
```

---

### Task 3.2: Create VisualEditor Component

**Files:**
- Create: `frontend/src/components/topology/VisualEditor.tsx`
- Create: `frontend/src/components/topology/VisualEditor.css`

**Step 1: Create VisualEditor.tsx**

```tsx
import { useCallback, useMemo, useEffect } from 'react';
import ReactFlow, {
  Background,
  Controls,
  useNodesState,
  useEdgesState,
  type Node,
  type Edge,
  type OnNodesChange,
} from 'reactflow';
import dagre from 'dagre';
import type { NodeGroup } from '../../types/api';
import 'reactflow/dist/style.css';
import './VisualEditor.css';

interface VisualEditorProps {
  nodeGroups: NodeGroup[];
  selectedGroupId: string | null;
  onSelectGroup: (groupId: string) => void;
  onAddGroup: () => void;
}

const dagreConfig = {
  nodesep: 80,
  ranksep: 120,
  rankdir: 'TB' as const,
};

function applyLayout(nodes: Node[], edges: Edge[]): { nodes: Node[]; edges: Edge[] } {
  if (nodes.length === 0) return { nodes, edges };

  const dagreGraph = new dagre.graphlib.Graph();
  dagreGraph.setDefaultEdgeLabel(() => ({}));
  dagreGraph.setGraph(dagreConfig);

  nodes.forEach(node => {
    dagreGraph.setNode(node.id, { width: 160, height: 80 });
  });

  edges.forEach(edge => {
    dagreGraph.setEdge(edge.source, edge.target);
  });

  dagre.layout(dagreGraph);

  const layoutedNodes = nodes.map(node => {
    const nodeWithPosition = dagreGraph.node(node.id);
    return {
      ...node,
      position: {
        x: nodeWithPosition.x - 80,
        y: nodeWithPosition.y - 40,
      },
    };
  });

  return { nodes: layoutedNodes, edges };
}

export default function VisualEditor({
  nodeGroups,
  selectedGroupId,
  onSelectGroup,
  onAddGroup,
}: VisualEditorProps) {
  // Convert nodeGroups to ReactFlow nodes
  const initialNodes = useMemo<Node[]>(() => {
    return nodeGroups.map(group => ({
      id: group.name,
      type: 'default',
      data: {
        label: (
          <div className="visual-node">
            <div className="visual-node__name">{group.name}</div>
            <div className="visual-node__replicas">{group.replicas} replica(s)</div>
          </div>
        ),
      },
      position: { x: 0, y: 0 },
      className: selectedGroupId === group.name ? 'visual-node--selected' : '',
    }));
  }, [nodeGroups, selectedGroupId]);

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);

  // Apply layout when nodes change
  useEffect(() => {
    const { nodes: layoutedNodes, edges: layoutedEdges } = applyLayout(initialNodes, []);
    setNodes(layoutedNodes);
    setEdges(layoutedEdges);
  }, [initialNodes, setNodes, setEdges]);

  const handleNodeClick = useCallback(
    (_event: React.MouseEvent, node: Node) => {
      onSelectGroup(node.id);
    },
    [onSelectGroup]
  );

  const handlePaneClick = useCallback(() => {
    // Deselect when clicking on pane
    onSelectGroup('');
  }, [onSelectGroup]);

  return (
    <div className="visual-editor">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onNodeClick={handleNodeClick}
        onPaneClick={handlePaneClick}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        minZoom={0.5}
        maxZoom={2}
        proOptions={{ hideAttribution: true }}
      >
        <Background gap={16} size={1} />
        <Controls showInteractive={false} />
      </ReactFlow>

      <button className="visual-editor__add-btn" onClick={onAddGroup}>
        + Add Node Group
      </button>
    </div>
  );
}
```

**Step 2: Create VisualEditor.css**

```css
.visual-editor {
  flex: 1;
  position: relative;
  background: #f8fafc;
}

.visual-editor__add-btn {
  position: absolute;
  bottom: 16px;
  left: 50%;
  transform: translateX(-50%);
  padding: 10px 20px;
  background: white;
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  font-size: 14px;
  cursor: pointer;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
}

.visual-editor__add-btn:hover {
  background: #f8fafc;
}

.visual-node {
  padding: 8px;
  text-align: center;
}

.visual-node__name {
  font-weight: 600;
  font-size: 13px;
  margin-bottom: 2px;
}

.visual-node__replicas {
  font-size: 11px;
  color: #64748b;
}

/* Selected node styling */
.react-flow__node.visual-node--selected {
  border: 2px solid #3b82f6;
  box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
}
```

**Step 3: Verify component compiles**

Run: `cd frontend && npm run build`
Expected: No compilation errors

**Step 4: Commit**

```bash
git add frontend/src/components/topology/VisualEditor.tsx frontend/src/components/topology/VisualEditor.css
git commit -m "feat(frontend): add VisualEditor component for low-code topology"
```

---

### Task 3.3: Refactor TopologyCreate with Dual Mode

**Files:**
- Modify: `frontend/src/pages/TopologyCreate.tsx`
- Modify: `frontend/src/pages/TopologyCreate.css`

**Step 1: Refactor TopologyCreate.tsx to use new components**

This is a major refactor. The new structure:

```tsx
import { useState, useCallback, useMemo } from 'react';
import Editor from '@monaco-editor/react';
import yaml from 'js-yaml';
import VisualEditor from '../components/topology/VisualEditor';
import ConfigPanel from '../components/topology/ConfigPanel';
import type { NetworkTopology, NodeGroup } from '../types/api';
import { apiClient } from '../api/client';
import './TopologyCreate.css';

interface TopologyCreateProps {
  isEdit?: boolean;
  initialTopology?: NetworkTopology;
  onCreated?: (name: string, namespace: string) => void;
  onCancel?: () => void;
}

type EditorMode = 'visual' | 'yaml';

const DEFAULT_NAMESPACE = 'kuro-experiment';
const DEFAULT_IMAGE = 'busybox:latest';

function generateDefaultName(): string {
  return `topology-${Date.now().toString(36)}`;
}

export default function TopologyCreate({
  isEdit = false,
  initialTopology,
  onCreated,
  onCancel,
}: TopologyCreateProps) {
  // Editor mode
  const [mode, setMode] = useState<EditorMode>('visual');

  // Basic info
  const [name, setName] = useState(initialTopology?.metadata.name || generateDefaultName());
  const [namespace, setNamespace] = useState(initialTopology?.metadata.namespace || DEFAULT_NAMESPACE);

  // Node groups
  const [nodeGroups, setNodeGroups] = useState<NodeGroup[]>(
    initialTopology?.spec?.nodeGroups || [
      { name: 'leader', replicas: 1, image: DEFAULT_IMAGE, labels: { role: 'leader' } },
      { name: 'follower', replicas: 2, image: DEFAULT_IMAGE, labels: { role: 'follower' } },
    ]
  );
  const [selectedGroupId, setSelectedGroupId] = useState<string | null>(null);

  // Submit state
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Generate YAML from state
  const yamlContent = useMemo(() => {
    const topology: NetworkTopology = {
      apiVersion: 'simulation.kuro.io/v1alpha1',
      kind: 'NetworkTopology',
      metadata: { name, namespace },
      spec: { nodeGroups },
    };
    return yaml.dump(topology, { indent: 2 });
  }, [name, namespace, nodeGroups]);

  // Parse YAML to state
  const parseYaml = useCallback((yamlStr: string) => {
    try {
      const parsed = yaml.load(yamlStr) as NetworkTopology;
      if (parsed.metadata?.name) setName(parsed.metadata.name);
      if (parsed.metadata?.namespace) setNamespace(parsed.metadata.namespace);
      if (parsed.spec?.nodeGroups) setNodeGroups(parsed.spec.nodeGroups);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Invalid YAML');
    }
  }, []);

  // Node group operations
  const handleAddGroup = useCallback(() => {
    const newGroupName = `group-${nodeGroups.length + 1}`;
    setNodeGroups(prev => [...prev, {
      name: newGroupName,
      replicas: 1,
      image: DEFAULT_IMAGE,
      labels: { role: newGroupName },
    }]);
    setSelectedGroupId(newGroupName);
  }, [nodeGroups.length]);

  const handleDeleteGroup = useCallback((groupId: string) => {
    setNodeGroups(prev => prev.filter(g => g.name !== groupId));
    if (selectedGroupId === groupId) {
      setSelectedGroupId(null);
    }
  }, [selectedGroupId]);

  const handleUpdateGroup = useCallback((groupId: string, updates: Partial<NodeGroup>) => {
    setNodeGroups(prev => prev.map(g => {
      if (g.name !== groupId) return g;
      
      // If name changed, update selectedGroupId too
      if (updates.name && updates.name !== groupId && selectedGroupId === groupId) {
        setSelectedGroupId(updates.name);
      }
      
      return { ...g, ...updates };
    }));
  }, [selectedGroupId]);

  // Submit
  const handleSubmit = useCallback(async () => {
    setIsSubmitting(true);
    setError(null);

    const topology: NetworkTopology = {
      apiVersion: 'simulation.kuro.io/v1alpha1',
      kind: 'NetworkTopology',
      metadata: { name, namespace },
      spec: { nodeGroups },
    };

    try {
      const response = isEdit && initialTopology
        ? await apiClient.updateTopology(topology)
        : await apiClient.createTopology(topology);

      if (response.success) {
        if (onCreated) {
          onCreated(name, namespace);
        }
      } else {
        setError(response.error || 'Failed to save topology');
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unknown error');
    } finally {
      setIsSubmitting(false);
    }
  }, [name, namespace, nodeGroups, isEdit, initialTopology, onCreated]);

  return (
    <div className="topology-create-v2">
      <div className="topology-create-v2__header">
        <div className="topology-create-v2__title">
          <h1>{isEdit ? 'Edit Topology' : 'Create Topology'}</h1>
        </div>
        
        <div className="topology-create-v2__mode-toggle">
          <button
            className={`topology-create-v2__mode-btn ${mode === 'visual' ? 'topology-create-v2__mode-btn--active' : ''}`}
            onClick={() => setMode('visual')}
          >
            Visual
          </button>
          <button
            className={`topology-create-v2__mode-btn ${mode === 'yaml' ? 'topology-create-v2__mode-btn--active' : ''}`}
            onClick={() => setMode('yaml')}
          >
            YAML
          </button>
        </div>
      </div>

      {error && (
        <div className="topology-create-v2__error">
          {error}
        </div>
      )}

      <div className="topology-create-v2__body">
        {mode === 'visual' ? (
          <>
            <VisualEditor
              nodeGroups={nodeGroups}
              selectedGroupId={selectedGroupId}
              onSelectGroup={setSelectedGroupId}
              onAddGroup={handleAddGroup}
            />
            <ConfigPanel
              name={name}
              namespace={namespace}
              nodeGroups={nodeGroups}
              selectedGroupId={selectedGroupId}
              onNameChange={setName}
              onNamespaceChange={setNamespace}
              onAddGroup={handleAddGroup}
              onSelectGroup={setSelectedGroupId}
              onDeleteGroup={handleDeleteGroup}
              onUpdateGroup={handleUpdateGroup}
              onSubmit={handleSubmit}
              submitLabel={isEdit ? 'Update Topology' : 'Create Topology'}
              isSubmitting={isSubmitting}
            />
          </>
        ) : (
          <div className="topology-create-v2__yaml">
            <Editor
              height="100%"
              language="yaml"
              value={yamlContent}
              onChange={value => value && parseYaml(value)}
              theme="vs-dark"
              options={{
                minimap: { enabled: false },
                fontSize: 14,
              }}
            />
            <div className="topology-create-v2__yaml-actions">
              <button
                className="topology-create-v2__submit"
                onClick={handleSubmit}
                disabled={isSubmitting}
              >
                {isEdit ? 'Update Topology' : 'Create Topology'}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
```

**Step 2: Update TopologyCreate.css**

```css
.topology-create-v2 {
  display: flex;
  flex-direction: column;
  height: 100%;
}

.topology-create-v2__header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px 24px;
  background: white;
  border-bottom: 1px solid #e2e8f0;
}

.topology-create-v2__title h1 {
  margin: 0;
  font-size: 20px;
  color: #1e293b;
}

.topology-create-v2__mode-toggle {
  display: flex;
  background: #f1f5f9;
  border-radius: 6px;
  padding: 2px;
}

.topology-create-v2__mode-btn {
  padding: 8px 16px;
  background: transparent;
  border: none;
  border-radius: 4px;
  font-size: 13px;
  cursor: pointer;
  color: #64748b;
}

.topology-create-v2__mode-btn--active {
  background: white;
  color: #1e293b;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
}

.topology-create-v2__error {
  margin: 16px 24px;
  padding: 12px;
  background: #fee2e2;
  color: #dc2626;
  border-radius: 8px;
}

.topology-create-v2__body {
  flex: 1;
  display: flex;
  overflow: hidden;
}

.topology-create-v2__yaml {
  flex: 1;
  display: flex;
  flex-direction: column;
}

.topology-create-v2__yaml-actions {
  padding: 16px;
  background: white;
  border-top: 1px solid #e2e8f0;
  display: flex;
  justify-content: flex-end;
}

.topology-create-v2__submit {
  padding: 10px 24px;
  background: #3b82f6;
  color: white;
  border: none;
  border-radius: 8px;
  font-size: 14px;
  cursor: pointer;
}

.topology-create-v2__submit:hover:not(:disabled) {
  background: #2563eb;
}

.topology-create-v2__submit:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
```

**Step 3: Verify page renders**

Run: `cd frontend && npm run dev`
Navigate to: `http://localhost:5173/topologies/create`
Expected: Visual mode shows canvas with default nodes, config panel on right

**Step 4: Test mode toggle**

Click "YAML" button
Expected: YAML editor appears with generated YAML

**Step 5: Commit**

```bash
git add frontend/src/pages/TopologyCreate.tsx frontend/src/pages/TopologyCreate.css
git commit -m "feat(frontend): refactor TopologyCreate with visual/yaml dual mode"
```

---

### Task 3.4: End-to-End Test Low-Code Mode

**Step 1: Test visual mode creation**

1. Navigate to `/topologies/create`
2. Keep default visual mode
3. Click on "leader" node
4. In config panel, change replicas to 2
5. Click "+ Add" to add new group
6. Name it "gateway", set replicas to 1
7. Click "Create Topology"
8. Expected: Redirects to topology list, new topology appears

**Step 2: Verify CRD created**

```bash
kubectl get networktopology -n kuro-experiment
kubectl describe networktopology <name> -n kuro-experiment
```
Expected: Topology exists with 3 node groups

**Step 3: Test YAML mode editing**

1. Navigate to `/topologies/create`
2. Click "YAML" mode
3. Edit YAML directly
4. Click "Create Topology"
5. Expected: Topology created from YAML

**Step 4: Test edit mode**

1. From topology list, click "Edit" on existing topology
2. Expected: Visual mode opens with existing node groups
3. Make changes, click "Update Topology"
4. Expected: Topology updated

**Step 5: Commit (if any fixes)**

```bash
git add -A
git commit -m "fix(frontend): low-code topology fixes"
```

---

### Task 3.5: Final Verification and Documentation

**Step 1: Run full frontend build**

```bash
cd frontend && npm run build
```
Expected: Build succeeds without errors

**Step 2: Run frontend tests**

```bash
cd frontend && npm test
```
Expected: All tests pass

**Step 3: Create summary commit**

```bash
git add -A
git commit -m "feat(frontend): complete frontend enhancement

- P1: Traffic Control CRUD with API integration
- P2: Grafana dashboard provisioning and external link
- P3: Visual/YAML dual-mode topology editor"
```

---

## Summary

| Phase | Tasks | Files Created | Files Modified |
|-------|-------|---------------|----------------|
| P1 | 4 | 4 | 4 |
| P2 | 3 | 0 | 3 |
| P3 | 5 | 4 | 2 |
| **Total** | **12** | **8** | **9** |
