# Topology & TrafficControl UI Enhancements Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enhance topology visualization with filtered/colored links and improve TrafficControl management with edit/import capabilities.

**Architecture:** 
1. Add multi-select TrafficControl filter in TopologyDetail sidebar to highlight corresponding edges with unique colors
2. Extend NodeDetailPanel to show related TrafficControls and topology context
3. Create TrafficControlEdit page reusing TrafficControlCreate form, add YAML import/export

**Tech Stack:** React, TypeScript, ReactFlow, Zustand, js-yaml

---

## Task 1: Add Color Palette Utility

**Files:**
- Create: `frontend/src/utils/colorPalette.ts`

**Step 1: Create color palette utility**

```typescript
// frontend/src/utils/colorPalette.ts

/**
 * Fixed color palette for TrafficControl visualization
 * High contrast colors for accessibility
 */
export const TRAFFIC_CONTROL_COLORS = [
  '#3b82f6', // Blue
  '#10b981', // Green
  '#f59e0b', // Amber
  '#ef4444', // Red
  '#8b5cf6', // Purple
  '#ec4899', // Pink
  '#06b6d4', // Cyan
  '#84cc16', // Lime
] as const;

/**
 * Get color for TrafficControl by index
 */
export function getTrafficControlColor(index: number): string {
  return TRAFFIC_CONTROL_COLORS[index % TRAFFIC_CONTROL_COLORS.length];
}

/**
 * Get color for TrafficControl by name (consistent hash)
 */
export function getTrafficControlColorByName(name: string): string {
  let hash = 0;
  for (let i = 0; i < name.length; i++) {
    hash = ((hash << 5) - hash) + name.charCodeAt(i);
    hash = hash & hash;
  }
  return TRAFFIC_CONTROL_COLORS[Math.abs(hash) % TRAFFIC_CONTROL_COLORS.length];
}
```

**Step 2: Commit**

```bash
git add frontend/src/utils/colorPalette.ts
git commit -m "feat(utils): add TrafficControl color palette utility"
```

---

## Task 2: Add TC Filter State to Store

**Files:**
- Modify: `frontend/src/stores/topologyStore.ts:25-30` (add state)
- Modify: `frontend/src/stores/topologyStore.ts:55-60` (add actions)

**Step 1: Add selectedTrafficControls state**

Add to `TopologyState` interface after `trafficControls`:

```typescript
// In TopologyState interface, after line ~26
trafficControls: TrafficControl[];
selectedTrafficControlIds: string[];  // NEW: IDs of selected TCs for filtering
```

**Step 2: Add initial state**

Add to initial state after `trafficControls: []`:

```typescript
selectedTrafficControlIds: [],
```

**Step 3: Add actions to interface**

Add to actions section:

```typescript
// Actions - TC Filter
setSelectedTrafficControlIds: (ids: string[]) => void;
toggleTrafficControlSelection: (id: string) => void;
clearTrafficControlSelection: () => void;
```

**Step 4: Implement actions in create()**

Add after `setTsnConfig`:

```typescript
// TC Filter Actions
setSelectedTrafficControlIds: (ids: string[]) => set({ selectedTrafficControlIds: ids }),

toggleTrafficControlSelection: (id: string) => {
  const current = get().selectedTrafficControlIds;
  const exists = current.includes(id);
  if (exists) {
    set({ selectedTrafficControlIds: current.filter(i => i !== id) });
  } else {
    set({ selectedTrafficControlIds: [...current, id] });
  }
},

clearTrafficControlSelection: () => set({ selectedTrafficControlIds: [] }),
```

**Step 5: Export selectors**

Add to hooks section:

```typescript
// Selector for TC filter
export const useTrafficControlFilter = () => useTopologyStore(useShallow((state) => ({
  trafficControls: state.trafficControls,
  selectedTrafficControlIds: state.selectedTrafficControlIds,
  toggleTrafficControlSelection: state.toggleTrafficControlSelection,
  clearTrafficControlSelection: state.clearTrafficControlSelection,
})));
```

**Step 6: Commit**

```bash
git add frontend/src/stores/topologyStore.ts
git commit -m "feat(store): add TrafficControl filter state for topology visualization"
```

---

## Task 3: Update TopologyCanvas for Colored Edges

**Files:**
- Modify: `frontend/src/components/topology/TopologyCanvas.tsx:20-25` (imports)
- Modify: `frontend/src/components/topology/TopologyCanvas.tsx:35-50` (props)
- Modify: `frontend/src/components/topology/TopologyCanvas.tsx:150-180` (edge transform)

**Step 1: Add imports**

Add after existing imports:

```typescript
import { getTrafficControlColorByName } from '../../utils/colorPalette';
```

**Step 2: Extend props interface**

Modify `TopologyCanvasProps` to add:

```typescript
export interface TopologyCanvasProps {
  // ... existing props
  trafficControlColors?: Map<string, string>;  // NEW: TC name -> color mapping
  highlightedLinkIds?: Set<string>;            // NEW: links to highlight
}
```

**Step 3: Modify edge transform function**

Replace `transformTopologyLinksToFlowEdges` function:

```typescript
function transformTopologyLinksToFlowEdges(
  links: TopologyLink[],
  selectedLinkId?: string,
  trafficControlColors?: Map<string, string>,
  highlightedLinkIds?: Set<string>
): Edge<CustomEdgeData>[] {
  const hasHighlight = highlightedLinkIds && highlightedLinkIds.size > 0;
  
  return links.map((link) => {
    const isSelected = link.id === selectedLinkId;
    const isHighlighted = highlightedLinkIds?.has(link.id) ?? false;
    const shouldDim = hasHighlight && !isHighlighted;
    
    // Get color from TC mapping or default
    const tcColor = trafficControlColors?.get(link.id);
    const strokeColor = isSelected ? '#3b82f6' : (tcColor || '#94a3b8');
    
    return {
      id: link.id,
      source: link.sourceId,
      target: link.targetId,
      type: 'smoothstep',
      animated: link.status === 'active',
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: isSelected ? '#3b82f6' : strokeColor,
      },
      style: {
        stroke: strokeColor,
        strokeWidth: isSelected ? 2.5 : (isHighlighted ? 2 : 1.5),
        opacity: shouldDim ? 0.15 : 1,
      },
      label: link.policy ? `${link.policy.bandwidth}` : undefined,
      labelStyle: { fill: '#64748b', fontWeight: 500, fontSize: 10, opacity: shouldDim ? 0.15 : 1 },
      labelBgStyle: { fill: '#ffffff', fillOpacity: shouldDim ? 0.5 : 0.9 },
      labelBgPadding: [4, 2] as [number, number],
      labelBgBorderRadius: 4,
      data: {
        link,
      } satisfies CustomEdgeData,
    };
  });
}
```

**Step 4: Update component to use new props**

In the component, update `initialEdges` useMemo:

```typescript
const initialEdges = useMemo(
  () => transformTopologyLinksToFlowEdges(
    topologyLinks, 
    selectedLinkId,
    trafficControlColors,
    highlightedLinkIds
  ),
  [topologyLinks, selectedLinkId, trafficControlColors, highlightedLinkIds]
);
```

**Step 5: Commit**

```bash
git add frontend/src/components/topology/TopologyCanvas.tsx
git commit -m "feat(canvas): support colored/filtered edges based on TrafficControl selection"
```

---

## Task 4: Create TrafficControlFilter Component

**Files:**
- Create: `frontend/src/components/topology/TrafficControlFilter.tsx`
- Create: `frontend/src/components/topology/TrafficControlFilter.css`

**Step 1: Create component**

```typescript
// frontend/src/components/topology/TrafficControlFilter.tsx

import { useMemo } from 'react';
import type { TrafficControl } from '../../types/api';
import { getTrafficControlColor } from '../../utils/colorPalette';
import './TrafficControlFilter.css';

interface TrafficControlFilterProps {
  trafficControls: TrafficControl[];
  selectedIds: string[];
  onToggle: (id: string) => void;
  onClear: () => void;
}

export function TrafficControlFilter({
  trafficControls,
  selectedIds,
  onToggle,
  onClear,
}: TrafficControlFilterProps) {
  // Build link to TC mapping info (simplified - show TC list)
  const tcWithColors = useMemo(() => 
    trafficControls.map((tc, index) => ({
      id: tc.metadata.uid,
      name: tc.metadata.name,
      color: getTrafficControlColor(index),
      policy: tc.spec.policy,
      phase: tc.status?.phase ?? 'Unknown',
    })),
    [trafficControls]
  );

  if (trafficControls.length === 0) {
    return (
      <div className="tc-filter tc-filter--empty">
        <span>No traffic controls</span>
      </div>
    );
  }

  return (
    <div className="tc-filter">
      <div className="tc-filter__header">
        <span className="tc-filter__count">{selectedIds.length} selected</span>
        {selectedIds.length > 0 && (
          <button className="tc-filter__clear" onClick={onClear}>
            Clear
          </button>
        )}
      </div>
      <div className="tc-filter__list">
        {tcWithColors.map((tc) => {
          const isSelected = selectedIds.includes(tc.id);
          return (
            <button
              key={tc.id}
              className={`tc-filter__item ${isSelected ? 'tc-filter__item--selected' : ''}`}
              onClick={() => onToggle(tc.id)}
            >
              <span 
                className="tc-filter__color" 
                style={{ backgroundColor: tc.color }}
              />
              <span className="tc-filter__name">{tc.name}</span>
              <span className="tc-filter__policy">
                {tc.policy.bandwidth}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
```

**Step 2: Create styles**

```css
/* frontend/src/components/topology/TrafficControlFilter.css */

.tc-filter {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.tc-filter--empty {
  color: #64748b;
  font-size: 13px;
  padding: 12px;
  text-align: center;
}

.tc-filter__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 4px 0;
}

.tc-filter__count {
  font-size: 12px;
  color: #64748b;
}

.tc-filter__clear {
  font-size: 12px;
  color: #3b82f6;
  background: none;
  border: none;
  cursor: pointer;
  padding: 2px 4px;
}

.tc-filter__clear:hover {
  text-decoration: underline;
}

.tc-filter__list {
  display: flex;
  flex-direction: column;
  gap: 4px;
  max-height: 300px;
  overflow-y: auto;
}

.tc-filter__item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 10px;
  background: #f8fafc;
  border: 1px solid #e2e8f0;
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.15s;
  text-align: left;
  width: 100%;
}

.tc-filter__item:hover {
  background: #f1f5f9;
  border-color: #cbd5e1;
}

.tc-filter__item--selected {
  background: #eff6ff;
  border-color: #3b82f6;
}

.tc-filter__color {
  width: 12px;
  height: 12px;
  border-radius: 50%;
  flex-shrink: 0;
}

.tc-filter__name {
  flex: 1;
  font-size: 13px;
  font-weight: 500;
  color: #1e293b;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.tc-filter__policy {
  font-size: 11px;
  color: #64748b;
  font-family: monospace;
}
```

**Step 3: Export from index**

Add to `frontend/src/components/topology/index.ts`:

```typescript
export { TrafficControlFilter } from './TrafficControlFilter';
```

**Step 4: Commit**

```bash
git add frontend/src/components/topology/TrafficControlFilter.tsx frontend/src/components/topology/TrafficControlFilter.css frontend/src/components/topology/index.ts
git commit -m "feat(components): add TrafficControlFilter for multi-select edge highlighting"
```

---

## Task 5: Integrate TC Filter into TopologyDetail

**Files:**
- Modify: `frontend/src/pages/TopologyDetail.tsx:425-445` (sidebar section)

**Step 1: Import the filter component**

Add to imports:

```typescript
import { TopologyCanvas, TrafficControlFilter } from '../components/topology';
```

**Step 2: Import the filter hook**

Add to store imports:

```typescript
import {
  useTopologyStore,
  useTopologyStats,
  useLocalView,
  useTopologyData,
  useTopologySelection,
  useTopologyUI,
  useTopologyActions,
  useNodeActions,
  useLinkActions,
  useTrafficControlFilter,  // NEW
} from '../stores';
```

**Step 3: Use filter hook in component**

Add after `const stats = useTopologyStats();`:

```typescript
// TC Filter state
const { 
  trafficControls: tcList,
  selectedTrafficControlIds,
  toggleTrafficControlSelection,
  clearTrafficControlSelection,
} = useTrafficControlFilter();
```

**Step 4: Compute highlighted links and colors**

Add after TC filter state:

```typescript
// Compute which links are highlighted and their colors
const trafficControlColors = useMemo(() => {
  const colorMap = new Map<string, string>();
  if (selectedTrafficControlIds.length === 0) return colorMap;
  
  trafficControls.forEach((tc, index) => {
    if (!selectedTrafficControlIds.includes(tc.metadata.uid)) return;
    
    const color = getTrafficControlColor(index);
    // Find links matching this TC's source/destination labels
    const sourceRole = tc.spec.source.matchLabels['role'];
    const destRole = tc.spec.destination.matchLabels['role'];
    
    links.forEach(link => {
      const sourceNode = nodes.find(n => n.id === link.sourceId);
      const targetNode = nodes.find(n => n.id === link.targetId);
      if (sourceNode?.labels?.role === sourceRole && targetNode?.labels?.role === destRole) {
        colorMap.set(link.id, color);
      }
    });
  });
  return colorMap;
}, [trafficControls, selectedTrafficControlIds, links, nodes]);

const highlightedLinkIds = useMemo(() => {
  return new Set(trafficControlColors.keys());
}, [trafficControlColors]);
```

**Step 5: Add getTrafficControlColor import**

```typescript
import { getTrafficControlColor } from '../utils/colorPalette';
```

**Step 6: Replace sidebar TC list with TrafficControlFilter**

Replace the existing TC list section:

```tsx
{/* Traffic Controls Filter */}
<div className="sidebar-section">
  <h4 className="sidebar-section-title">Filter by Traffic Control</h4>
  <TrafficControlFilter
    trafficControls={trafficControls}
    selectedIds={selectedTrafficControlIds}
    onToggle={toggleTrafficControlSelection}
    onClear={clearTrafficControlSelection}
  />
</div>
```

**Step 7: Pass new props to TopologyCanvas**

Update TopologyCanvas usage:

```tsx
<TopologyCanvas
  nodes={displayNodes}
  links={displayLinks}
  selectedNodeId={selectedNode?.id}
  selectedLinkId={selectedLink?.id}
  onNodeClick={handleNodeClick}
  onEdgeClick={handleEdgeClick}
  onPaneClick={actions.clearSelection}
  onSelectionChange={handleSelectionChange}
  fitView
  showMiniMap
  topologyId={`${namespace}-${topologyName}`}
  trafficControlColors={trafficControlColors}
  highlightedLinkIds={highlightedLinkIds}
/>
```

**Step 8: Commit**

```bash
git add frontend/src/pages/TopologyDetail.tsx
git commit -m "feat(topology): integrate TrafficControl filter for edge highlighting"
```

---

## Task 6: Enhance NodeDetailPanel with Context Info

**Files:**
- Modify: `frontend/src/pages/TopologyDetail.tsx:75-135` (NodeDetailPanel)

**Step 1: Add helper function to find related TCs**

Add before NodeDetailPanel:

```typescript
// Find TrafficControls related to a node
function findRelatedTrafficControls(
  node: TopologyNode, 
  trafficControls: TrafficControl[]
): TrafficControl[] {
  const nodeRole = node.labels?.role;
  if (!nodeRole) return [];
  
  return trafficControls.filter(tc => {
    const sourceRole = tc.spec.source.matchLabels['role'];
    const destRole = tc.spec.destination.matchLabels['role'];
    return nodeRole === sourceRole || nodeRole === destRole;
  });
}
```

**Step 2: Update NodeDetailPanel to show new fields**

Replace the NodeDetailPanel function:

```tsx
function NodeDetailPanel() {
  const { selectedNode } = useTopologySelection();
  const { clearSelection } = useNodeActions();
  const { currentTopology, trafficControls, isInLocalView } = useTopologyStore(useShallow((state) => ({
    currentTopology: state.currentTopology,
    trafficControls: state.trafficControls,
    isInLocalView: state.localViewNodeId !== null,
  })));
  const { enterLocalView } = useTopologyActions();

  if (!selectedNode) return null;

  const statusClass = `detail-field__value detail-field__value--status detail-field__value--status--${selectedNode.status}`;
  const relatedTCs = findRelatedTrafficControls(selectedNode, trafficControls);
  const handleEnterLocalView = () => {
    enterLocalView(selectedNode.id);
  };

  return (
    <div className="detail-panel">
      <div className="detail-panel__header">
        <h3 className="detail-panel__title">Node Details</h3>
        <button className="detail-panel__close" onClick={clearSelection}>×</button>
      </div>
      <div className="detail-panel__body">
        {/* Basic Info */}
        <div className="detail-field">
          <span className="detail-field__label">Name</span>
          <span className="detail-field__value">{selectedNode.name}</span>
        </div>
        <div className="detail-field">
          <span className="detail-field__label">ID</span>
          <span className="detail-field__value detail-field__value--mono">{selectedNode.id}</span>
        </div>
        <div className="detail-field">
          <span className="detail-field__label">IP Address</span>
          <span className="detail-field__value detail-field__value--mono">{selectedNode.ip}</span>
        </div>
        <div className="detail-field">
          <span className="detail-field__label">Role</span>
          <span className="detail-field__value">
            <span className="role-badge">{selectedNode.role}</span>
          </span>
        </div>
        <div className="detail-field">
          <span className="detail-field__label">Status</span>
          <span className={statusClass}>{selectedNode.status}</span>
        </div>
        <div className="detail-field">
          <span className="detail-field__label">Group</span>
          <span className="detail-field__value">{selectedNode.groupId}</span>
        </div>
        
        {/* NEW: Context Info */}
        <div className="detail-section-title">Context</div>
        <div className="detail-field">
          <span className="detail-field__label">Namespace</span>
          <span className="detail-field__value detail-field__value--mono">
            {currentTopology?.metadata.namespace || 'kuro-experiment'}
          </span>
        </div>
        <div className="detail-field">
          <span className="detail-field__label">Topology</span>
          <span className="detail-field__value">
            {currentTopology?.metadata.name || 'unknown'}
          </span>
        </div>
        
        {/* NEW: Related TrafficControls */}
        <div className="detail-section-title">Traffic Controls ({relatedTCs.length})</div>
        {relatedTCs.length === 0 ? (
          <div className="detail-field__empty">No traffic controls</div>
        ) : (
          <div className="detail-field__tc-list">
            {relatedTCs.map((tc) => (
              <div key={tc.metadata.uid} className="detail-field__tc-item">
                <span className="detail-field__tc-name">{tc.metadata.name}</span>
                <span className="detail-field__tc-role">
                  {tc.spec.source.matchLabels['role'] === selectedNode.labels?.role ? 'source' : 'destination'}
                </span>
              </div>
            ))}
          </div>
        )}
        
        <div className="detail-section-title">Labels</div>
        <div className="detail-field__labels">
          {Object.entries(selectedNode.labels).map(([key, value]) => (
            <span key={key} className="label-tag">
              {key}={value}
            </span>
          ))}
        </div>
        
        {/* Local View Button */}
        {!isInLocalView && (
          <div className="detail-section-title">Actions</div>
        )}
        {!isInLocalView && (
          <button 
            className="btn btn--primary local-view-btn"
            onClick={handleEnterLocalView}
          >
            🔍 Enter Local View
          </button>
        )}
        {isInLocalView && (
          <div className="local-view-indicator">
            Currently viewing this node's local view
          </div>
        )}
      </div>
    </div>
  );
}
```

**Step 3: Add CSS for new fields**

Add to `frontend/src/pages/TopologyDetail.css`:

```css
/* Detail Panel - TC List */
.detail-field__tc-list {
  display: flex;
  flex-direction: column;
  gap: 4px;
  margin-bottom: 8px;
}

.detail-field__tc-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 6px 8px;
  background: #f8fafc;
  border-radius: 4px;
  font-size: 12px;
}

.detail-field__tc-name {
  color: #1e293b;
  font-weight: 500;
}

.detail-field__tc-role {
  color: #64748b;
  font-size: 11px;
  text-transform: uppercase;
}

.detail-field__empty {
  color: #94a3b8;
  font-size: 12px;
  font-style: italic;
  padding: 4px 0;
}
```

**Step 4: Commit**

```bash
git add frontend/src/pages/TopologyDetail.tsx frontend/src/pages/TopologyDetail.css
git commit -m "feat(node-details): add namespace, topology, and related TrafficControls info"
```

---

## Task 7: Add TrafficControl YAML Utilities

**Files:**
- Modify: `frontend/src/utils/topologyYaml.ts` (extend for TrafficControl)

**Step 1: Add TrafficControl YAML functions**

Add to end of file:

```typescript
// ============================================================================
// TrafficControl YAML Utilities
// ============================================================================

/**
 * Export TrafficControl to YAML string
 */
export function exportTrafficControlToYaml(tc: TrafficControl): string {
  const exportData: TrafficControl = {
    apiVersion: tc.apiVersion || 'simulation.kuro.io/v1alpha1',
    kind: tc.kind || 'TrafficControl',
    metadata: {
      name: tc.metadata.name,
      namespace: tc.metadata.namespace || 'kuro-experiment',
      labels: tc.metadata.labels,
      annotations: tc.metadata.annotations,
      uid: '',
      creationTimestamp: '',
    },
    spec: {
      source: tc.spec.source,
      destination: tc.spec.destination,
      policy: tc.spec.policy,
    },
  };

  return yaml.dump(exportData, {
    indent: 2,
    lineWidth: -1,
    noRefs: true,
    sortKeys: false,
  });
}

/**
 * Download TrafficControl as YAML file
 */
export function downloadTrafficControlYaml(tc: TrafficControl): void {
  const yamlContent = exportTrafficControlToYaml(tc);
  const blob = new Blob([yamlContent], { type: 'text/yaml' });
  const url = URL.createObjectURL(blob);
  
  const link = document.createElement('a');
  link.href = url;
  link.download = `${tc.metadata.name}.yaml`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

/**
 * Parse imported TrafficControl YAML
 */
export function parseTrafficControlYaml(content: string): TrafficControl | null {
  try {
    const data = yaml.load(content) as Record<string, unknown>;
    
    if (data.kind !== 'TrafficControl') {
      return null;
    }
    
    return data as unknown as TrafficControl;
  } catch {
    return null;
  }
}
```

**Step 2: Add TrafficControl import to types**

Add import at top if not present:

```typescript
import type { NetworkTopology, NodeGroup, TrafficControl } from '../types/api';
```

**Step 3: Commit**

```bash
git add frontend/src/utils/topologyYaml.ts
git commit -m "feat(utils): add TrafficControl YAML export/import utilities"
```

---

## Task 8: Create TrafficControlEdit Page

**Files:**
- Create: `frontend/src/pages/TrafficControlEdit.tsx`
- Create: `frontend/src/pages/TrafficControlEdit.css`

**Step 1: Create edit page (reuse TrafficControlCreate logic)**

```typescript
// frontend/src/pages/TrafficControlEdit.tsx

import { useState, useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { apiClient } from '../api/client';
import { validatePolicy, type PolicyValidationResult } from '../utils/policyValidator';
import type { NetworkTopology, TrafficControl, NodeGroup } from '../types/api';
import './TrafficControlEdit.css';

interface TrafficControlEditProps {
  onUpdated?: (name: string, namespace: string) => void;
  onCancel?: () => void;
}

function TrafficControlEdit({ onUpdated, onCancel }: TrafficControlEditProps) {
  const navigate = useNavigate();
  const { name: tcName, namespace: tcNamespace } = useParams<{ name: string; namespace: string }>();
  
  // Form state
  const [name, setName] = useState('');
  const [namespace] = useState(tcNamespace || 'kuro-experiment');
  const [selectedTopology, setSelectedTopology] = useState('');
  const [sourceGroup, setSourceGroup] = useState('');
  const [destGroup, setDestGroup] = useState('');
  const [policy, setPolicy] = useState({
    bandwidth: '10Mbps',
    latency: '10ms',
    jitter: '5ms',
    packetLoss: '0.1%',
  });

  // Data state
  const [originalTC, setOriginalTC] = useState<TrafficControl | null>(null);
  const [topologies, setTopologies] = useState<NetworkTopology[]>([]);
  const [nodeGroups, setNodeGroups] = useState<NodeGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [policyErrors, setPolicyErrors] = useState<Record<string, string>>({});

  // Load TrafficControl and topologies on mount
  useEffect(() => {
    loadData();
  }, [tcName, tcNamespace]);

  const loadData = async () => {
    setLoading(true);
    setError(null);

    // Load TrafficControl
    const tcResponse = await apiClient.getTrafficControl(tcName!, namespace);
    if (!tcResponse.success || !tcResponse.data) {
      setError(tcResponse.error || 'Failed to load traffic control');
      setLoading(false);
      return;
    }
    
    const tc = tcResponse.data;
    setOriginalTC(tc);
    setName(tc.metadata.name);
    setPolicy(tc.spec.policy);
    
    // Extract source/dest groups from matchLabels
    const sourceGroupLabel = tc.spec.source.matchLabels['kuro.io/node-group'];
    const destGroupLabel = tc.spec.destination.matchLabels['kuro.io/node-group'];
    
    // Load topologies
    const topologiesResponse = await apiClient.listTopologies(namespace);
    if (topologiesResponse.success && topologiesResponse.data) {
      setTopologies(topologiesResponse.data.items);
      
      // Try to find matching topology
      const matchingTopology = topologiesResponse.data.items.find(t => 
        t.spec.nodeGroups?.some(g => g.name === sourceGroupLabel)
      );
      
      if (matchingTopology) {
        setSelectedTopology(matchingTopology.metadata.name);
        setNodeGroups(matchingTopology.spec.nodeGroups || []);
        setSourceGroup(sourceGroupLabel || '');
        setDestGroup(destGroupLabel || '');
      }
    }

    setLoading(false);
  };

  // Update node groups when topology changes
  useEffect(() => {
    if (selectedTopology) {
      const topology = topologies.find((t) => t.metadata.name === selectedTopology);
      if (topology?.spec?.nodeGroups) {
        setNodeGroups(topology.spec.nodeGroups);
      }
    }
  }, [selectedTopology, topologies]);

  // Handle policy field change
  const handlePolicyChange = (field: keyof typeof policy, value: string) => {
    setPolicy((prev) => ({ ...prev, [field]: value }));
    if (policyErrors[field]) {
      setPolicyErrors((prev) => {
        const next = { ...prev };
        delete next[field];
        return next;
      });
    }
  };

  // Validate form
  const validateForm = (): string | null {
    if (!sourceGroup) return 'Please select a source node group';
    if (!destGroup) return 'Please select a destination node group';
    if (sourceGroup === destGroup) return 'Source and destination must be different';
    
    const policyValidation: PolicyValidationResult = validatePolicy(policy);
    if (!policyValidation.isValid) {
      setPolicyErrors(policyValidation.errors);
      return 'Please fix policy validation errors';
    }
    
    return null;
  };

  // Handle form submission
  const handleSubmit = async () => {
    const validationError = validateForm();
    if (validationError) {
      setError(validationError);
      return;
    }

    setSubmitting(true);
    setError(null);

    const updatedTC: TrafficControl = {
      ...originalTC!,
      spec: {
        source: {
          matchLabels: { 'kuro.io/node-group': sourceGroup },
        },
        destination: {
          matchLabels: { 'kuro.io/node-group': destGroup },
        },
        policy: {
          bandwidth: policy.bandwidth,
          latency: policy.latency,
          jitter: policy.jitter,
          packetLoss: policy.packetLoss,
        },
      },
    };

    const response = await apiClient.updateTrafficControl(updatedTC);

    if (response.success) {
      if (onUpdated) {
        onUpdated(name, namespace);
      } else {
        navigate('/traffic-controls');
      }
    } else {
      setError(response.error || 'Failed to update traffic control');
    }

    setSubmitting(false);
  };

  // Handle cancel
  const handleCancel = () => {
    if (onCancel) {
      onCancel();
    } else {
      navigate('/traffic-controls');
    }
  };

  if (loading) {
    return (
      <div className="tc-edit">
        <div className="tc-edit__loading">
          <div className="tc-edit__spinner" />
          <span>Loading traffic control...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="tc-edit">
      <header className="tc-edit__header">
        <div className="tc-edit__title-section">
          <h1 className="tc-edit__title">Edit Traffic Control</h1>
          <p className="tc-edit__subtitle">
            {name} in {namespace}
          </p>
        </div>
        <div className="tc-edit__header-actions">
          <button className="btn btn--secondary" onClick={handleCancel} disabled={submitting}>
            Cancel
          </button>
          <button className="btn btn--primary" onClick={handleSubmit} disabled={submitting}>
            {submitting ? 'Saving...' : 'Save Changes'}
          </button>
        </div>
      </header>

      {error && (
        <div className="tc-edit__error">
          <span>⚠️ {error}</span>
        </div>
      )}

      <div className="tc-edit__content">
        <div className="tc-edit__form">
          {/* Topology Selection */}
          <section className="form-section">
            <h2 className="form-section__title">Topology & Groups</h2>
            <div className="form-group">
              <label className="form-label">Topology</label>
              <select
                className="form-select"
                value={selectedTopology}
                onChange={(e) => setSelectedTopology(e.target.value)}
                disabled={submitting}
              >
                <option value="">Select topology...</option>
                {topologies.map((t) => (
                  <option key={t.metadata.name} value={t.metadata.name}>
                    {t.metadata.name}
                  </option>
                ))}
              </select>
            </div>
            <div className="form-row">
              <div className="form-group">
                <label className="form-label">Source Group</label>
                <select
                  className="form-select"
                  value={sourceGroup}
                  onChange={(e) => setSourceGroup(e.target.value)}
                  disabled={submitting || !selectedTopology}
                >
                  <option value="">Select...</option>
                  {nodeGroups.map((g) => (
                    <option key={g.name} value={g.name}>{g.name}</option>
                  ))}
                </select>
              </div>
              <div className="form-group">
                <label className="form-label">Destination Group</label>
                <select
                  className="form-select"
                  value={destGroup}
                  onChange={(e) => setDestGroup(e.target.value)}
                  disabled={submitting || !selectedTopology}
                >
                  <option value="">Select...</option>
                  {nodeGroups.map((g) => (
                    <option key={g.name} value={g.name}>{g.name}</option>
                  ))}
                </select>
              </div>
            </div>
          </section>

          {/* Policy Section */}
          <section className="form-section">
            <h2 className="form-section__title">Traffic Policy</h2>
            <div className="form-row">
              <div className="form-group">
                <label className="form-label">Bandwidth</label>
                <input
                  type="text"
                  className={`form-input${policyErrors.bandwidth ? ' form-input--error' : ''}`}
                  value={policy.bandwidth}
                  onChange={(e) => handlePolicyChange('bandwidth', e.target.value)}
                  disabled={submitting}
                />
              </div>
              <div className="form-group">
                <label className="form-label">Latency</label>
                <input
                  type="text"
                  className={`form-input${policyErrors.latency ? ' form-input--error' : ''}`}
                  value={policy.latency}
                  onChange={(e) => handlePolicyChange('latency', e.target.value)}
                  disabled={submitting}
                />
              </div>
            </div>
            <div className="form-row">
              <div className="form-group">
                <label className="form-label">Jitter</label>
                <input
                  type="text"
                  className={`form-input${policyErrors.jitter ? ' form-input--error' : ''}`}
                  value={policy.jitter}
                  onChange={(e) => handlePolicyChange('jitter', e.target.value)}
                  disabled={submitting}
                />
              </div>
              <div className="form-group">
                <label className="form-label">Packet Loss</label>
                <input
                  type="text"
                  className={`form-input${policyErrors.packetLoss ? ' form-input--error' : ''}`}
                  value={policy.packetLoss}
                  onChange={(e) => handlePolicyChange('packetLoss', e.target.value)}
                  disabled={submitting}
                />
              </div>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}

export default TrafficControlEdit;
```

**Step 2: Create CSS (copy from TrafficControlCreate with minor changes)**

```css
/* frontend/src/pages/TrafficControlEdit.css */

.tc-edit {
  padding: 24px;
  max-width: 900px;
  margin: 0 auto;
}

.tc-edit__header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 24px;
}

.tc-edit__title {
  margin: 0;
  font-size: 24px;
  font-weight: 600;
  color: #1e293b;
}

.tc-edit__subtitle {
  margin: 4px 0 0;
  color: #64748b;
  font-size: 14px;
}

.tc-edit__header-actions {
  display: flex;
  gap: 12px;
}

.tc-edit__error {
  padding: 12px 16px;
  background: #fef2f2;
  border: 1px solid #fecaca;
  border-radius: 8px;
  color: #dc2626;
  margin-bottom: 24px;
}

.tc-edit__content {
  background: #ffffff;
  border: 1px solid #e2e8f0;
  border-radius: 12px;
  padding: 24px;
}

.tc-edit__form {
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.tc-edit__loading {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 48px;
  color: #64748b;
  gap: 16px;
}

.tc-edit__spinner {
  width: 32px;
  height: 32px;
  border: 3px solid #e2e8f0;
  border-top-color: #3b82f6;
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

/* Reuse form styles from TrafficControlCreate */
.form-section {
  margin-bottom: 8px;
}

.form-section__title {
  margin: 0 0 16px;
  font-size: 16px;
  font-weight: 600;
  color: #1e293b;
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.form-label {
  font-size: 13px;
  font-weight: 500;
  color: #475569;
}

.form-input,
.form-select {
  padding: 10px 12px;
  border: 1px solid #d1d5db;
  border-radius: 6px;
  font-size: 14px;
  transition: border-color 0.15s, box-shadow 0.15s;
}

.form-input:focus,
.form-select:focus {
  outline: none;
  border-color: #3b82f6;
  box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
}

.form-input--error {
  border-color: #ef4444;
}

.form-input--readonly {
  background: #f8fafc;
  color: #64748b;
}

.form-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}
```

**Step 3: Export from pages/index.ts**

```typescript
export { default as TrafficControlEdit } from './TrafficControlEdit';
```

**Step 4: Commit**

```bash
git add frontend/src/pages/TrafficControlEdit.tsx frontend/src/pages/TrafficControlEdit.css frontend/src/pages/index.ts
git commit -m "feat(pages): add TrafficControlEdit page for editing existing controls"
```

---

## Task 9: Add Routes and Update TrafficControlList

**Files:**
- Modify: `frontend/src/App.tsx` (add route)
- Modify: `frontend/src/pages/TrafficControlList.tsx` (add edit, import, export)

**Step 1: Add route in App.tsx**

Add import:

```typescript
import { TrafficControlList, TrafficControlCreate, TrafficControlEdit } from './pages';
```

Add route after TrafficControlCreate route:

```tsx
<Route 
  path="/traffic-controls/:namespace/:name/edit"
  element={<TrafficControlEdit />}
/>
```

**Step 2: Update TrafficControlList with edit, import, export**

Add imports:

```typescript
import { useRef } from 'react';
import { 
  downloadTrafficControlYaml, 
  parseTrafficControlYaml, 
  readFileAsText 
} from '../utils/topologyYaml';
```

Add state and ref:

```typescript
const fileInputRef = useRef<HTMLInputElement>(null);
const [importError, setImportError] = useState<string | null>(null);
const [importing, setImporting] = useState(false);
```

Add handlers:

```typescript
const handleEditTrafficControl = (name: string) => {
  navigate(`/traffic-controls/kuro-experiment/${name}/edit`);
};

const handleExportTrafficControl = (tc: TrafficControl) => {
  downloadTrafficControlYaml(tc);
};

const handleImportClick = () => {
  fileInputRef.current?.click();
};

const handleImportFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
  const file = e.target.files?.[0];
  if (!file) return;
  
  setImportError(null);
  setImporting(true);
  
  try {
    const content = await readFileAsText(file);
    const tc = parseTrafficControlYaml(content);
    
    if (!tc) {
      setImportError('Invalid TrafficControl YAML');
      setImporting(false);
      return;
    }
    
    const response = await apiClient.createTrafficControl(tc);
    if (response.success) {
      fetchTrafficControls();
    } else {
      setImportError(response.error || 'Failed to import');
    }
  } catch (err) {
    setImportError('Failed to read file');
  }
  
  setImporting(false);
  e.target.value = '';
};
```

Add hidden file input in JSX:

```tsx
<input
  ref={fileInputRef}
  type="file"
  accept=".yaml,.yml"
  onChange={handleImportFile}
  style={{ display: 'none' }}
/>
```

Update header actions to include import:

```tsx
<div className="tc-list__header-actions">
  <button className="btn btn--secondary" onClick={handleImportClick} disabled={importing}>
    <span className="btn__icon">📥</span>
    Import YAML
  </button>
  <button className="btn btn--primary" onClick={handleCreateTrafficControl}>
    <span className="btn__icon">➕</span>
    Create Traffic Control
  </button>
</div>
```

Add edit and export buttons to TC cards (find the card action buttons section):

```tsx
<div className="tc-card__actions">
  <button 
    className="tc-card__btn" 
    onClick={() => handleEditTrafficControl(tc.metadata.name)}
    title="Edit"
  >
    ✏️
  </button>
  <button 
    className="tc-card__btn" 
    onClick={() => handleExportTrafficControl(tc)}
    title="Export YAML"
  >
    📥
  </button>
  <button 
    className="tc-card__btn tc-card__btn--danger" 
    onClick={() => handleDeleteTrafficControl(tc.metadata.name)}
    title="Delete"
  >
    🗑️
  </button>
</div>
```

**Step 3: Add CSS for card actions**

Add to `frontend/src/pages/TrafficControlList.css`:

```css
.tc-card__actions {
  display: flex;
  gap: 4px;
  margin-top: 12px;
  padding-top: 12px;
  border-top: 1px solid #e2e8f0;
}

.tc-card__btn {
  padding: 6px 10px;
  background: #f8fafc;
  border: 1px solid #e2e8f0;
  border-radius: 4px;
  cursor: pointer;
  font-size: 14px;
  transition: all 0.15s;
}

.tc-card__btn:hover {
  background: #f1f5f9;
  border-color: #cbd5e1;
}

.tc-card__btn--danger:hover {
  background: #fef2f2;
  border-color: #fecaca;
}
```

**Step 4: Commit**

```bash
git add frontend/src/App.tsx frontend/src/pages/TrafficControlList.tsx frontend/src/pages/TrafficControlList.css
git commit -m "feat(traffic-control): add edit, import, export functionality to list page"
```

---

## Task 10: Add API Client Method for getTrafficControl

**Files:**
- Modify: `frontend/src/api/client.ts:180-200` (add getTrafficControl)

**Step 1: Add getTrafficControl method to interface**

In `frontend/src/types/api.ts`, ensure `KuroApiClient` interface has:

```typescript
getTrafficControl(name: string, namespace?: string): Promise<ApiResponse<TrafficControl>>;
```

**Step 2: Implement in MockKuroApiClient**

Add after `listTrafficControls`:

```typescript
async getTrafficControl(name: string, namespace: string = 'kuro-experiment'): Promise<ApiResponse<TrafficControl>> {
  await delay(100);
  
  const tc = this.trafficControls.find(
    (t) => t.metadata.name === name && t.metadata.namespace === namespace
  );
  
  if (!tc) {
    return {
      success: false,
      error: `TrafficControl '${name}' not found`,
    };
  }
  
  return { success: true, data: tc };
}
```

**Step 3: Commit**

```bash
git add frontend/src/api/client.ts frontend/src/types/api.ts
git commit -m "feat(api): add getTrafficControl method"
```

---

## Task 11: Final Verification

**Step 1: Build frontend**

```bash
cd frontend && npm run build
```

Expected: Build succeeds with no errors

**Step 2: Manual testing checklist**

1. Navigate to `/topologies/kuro-experiment/topology-demo`
2. Test TC filter: select/deselect TCs, verify edges highlight/dim
3. Click node, verify Node Details shows namespace, topology, and related TCs
4. Navigate to `/traffic-controls`
5. Test edit: click edit button, modify TC, save
6. Test export: click export button, download YAML
7. Test import: click import button, select YAML file

**Step 3: Commit verification**

```bash
git log --oneline -12
```

**Step 4: Final commit**

```bash
git add -A
git commit -m "feat: complete topology and traffic control UI enhancements

- Add multi-select TrafficControl filter for edge highlighting
- Add colored edges based on TrafficControl selection
- Enhance NodeDetailPanel with namespace, topology, and related TCs
- Add TrafficControlEdit page for editing existing controls
- Add import/export YAML functionality for TrafficControls"
```

---

## Summary

| Task | Description |
|------|-------------|
| 1 | Add color palette utility |
| 2 | Add TC filter state to store |
| 3 | Update TopologyCanvas for colored edges |
| 4 | Create TrafficControlFilter component |
| 5 | Integrate TC filter into TopologyDetail |
| 6 | Enhance NodeDetailPanel with context info |
| 7 | Add TrafficControl YAML utilities |
| 8 | Create TrafficControlEdit page |
| 9 | Add routes and update TrafficControlList |
| 10 | Add getTrafficControl API method |
| 11 | Final verification |
