# Kuro Low-Code Editor Development Plan

**Version:** 2.0  
**Date:** 2026-02-18  
**Status:** Pending Development

---

## Background

The current Kuro frontend supports creating topologies through a YAML editor, but users want a more intuitive low-code platform:
- Add nodes through drag and drop
- Configure image, role, labels, etc. in configuration panels
- Configure network simulation parameters for links between nodes

---

## Backend Capability Analysis

### NodeGroup CRD Support

```yaml
spec:
  nodeGroups:
    - name: drones
      replicas: 5
      image: nicolaka/netshoot
      command: ["sleep", "infinity"]
      labels:
        role: drone
        team: red
      userProgram:
        source: |
          print("Hello from drone")
        mountPath: /app
        filename: main.py
```

### TrafficControl CRD Support

```yaml
spec:
  priority: 100
  source:
    matchLabels:
      role: drone
  destination:
    matchLabels:
      role: ground-station
  policy:
    bandwidth: 10Mbps
    latency: 50ms
    jitter: 10ms
    packetLoss: 0.5%
```

### Backend API

| Endpoint | Method | Function |
|----------|--------|----------|
| `/api/v1/topology` | GET | Get topology node list |
| `/api/v1/policy/link` | POST | Apply link policy |
| `/api/v1/policy/pod` | POST | Apply Pod policy |
| `/api/v1/policy/node` | POST | Apply node policy |

---

## Feature Development Plan

### Phase 1: Low-Code Editor Basics (High Priority)

#### LC-001: Node Palette - Node Toolbar

**Goal:** Provide a draggable node type toolbar

**Implementation Details:**

1. Create `NodePalette` component (`frontend/src/components/topology/NodePalette.tsx`)
   ```tsx
   interface NodePaletteProps {
     nodeTypes: NodeTypeDefinition[];
     onNodeDragStart: (type: string) => void;
   }
   ```

2. Create `DraggableNodeItem` component
   ```tsx
   interface DraggableNodeItemProps {
     type: string;
     icon: string;
     label: string;
     color: string;
   }
   ```

3. Predefined node types:
   ```typescript
   const NODE_TYPES = [
     { type: 'drone', icon: '🚁', label: 'Drone', color: '#3b82f6' },
     { type: 'ground-station', icon: '📡', label: 'Ground Station', color: '#10b981' },
     { type: 'gateway', icon: '🔀', label: 'Gateway', color: '#8b5cf6' },
     { type: 'server', icon: '🖥️', label: 'Server', color: '#6366f1' },
     { type: 'client', icon: '💻', label: 'Client', color: '#f59e0b' },
     { type: 'custom', icon: '📦', label: 'Custom', color: '#6b7280' },
   ];
   ```

4. Drag handling:
   ```typescript
   const onDragStart = (event: React.DragEvent, nodeType: string) => {
     event.dataTransfer.setData('application/reactflow', nodeType);
     event.dataTransfer.effectAllowed = 'move';
   };
   ```

**File List:**
- `frontend/src/components/topology/NodePalette.tsx`
- `frontend/src/components/topology/NodePalette.css`
- `frontend/src/components/topology/DraggableNodeItem.tsx`
- `frontend/src/components/topology/index.ts` (update exports)

**Test Steps:**
1. Run `npm run test:run`
2. Navigate to topology creation page
3. Verify node toolbar displays
4. Drag node to canvas
5. Verify node added successfully

---

#### LC-002: Node Configuration Panel - Node Configuration Panel

**Goal:** Display configuration panel after clicking a node, supporting configuration of all NodeGroup fields

**Implementation Details:**

1. Create `NodeConfigPanel` component (`frontend/src/components/topology/NodeConfigPanel.tsx`)
   ```tsx
   interface NodeConfigPanelProps {
     node: TopologyNode | null;
     onUpdate: (node: Partial<TopologyNode>) => void;
     onClose: () => void;
   }
   ```

2. Create form field components:
   - `ImageInput` - Image selection/input
   - `LabelsEditor` - Label key-value editor
   - `CommandInput` - Startup command editor
   - `ReplicasInput` - Replica count input
   - `UserProgramEditor` - User code editor

3. Form validation:
   ```typescript
   const validateNodeConfig = (config: NodeGroupConfig): ValidationResult => {
     const errors: string[] = [];
     if (!config.name) errors.push('Name is required');
     if (!config.image) errors.push('Image is required');
     if (config.replicas < 1) errors.push('Replicas must be at least 1');
     return { valid: errors.length === 0, errors };
   };
   ```

**File List:**
- `frontend/src/components/topology/NodeConfigPanel.tsx`
- `frontend/src/components/topology/NodeConfigPanel.css`
- `frontend/src/components/topology/ImageInput.tsx`
- `frontend/src/components/topology/LabelsEditor.tsx`
- `frontend/src/components/topology/CommandInput.tsx`
- `frontend/src/types/nodeConfig.ts`

**Test Steps:**
1. Run `npm run test:run`
2. Drag to add a new node
3. Click node to open configuration panel
4. Modify various fields
5. Verify real-time preview updates

---

#### LC-003: Link Drawing - Link Drawing Feature

**Goal:** Support creating link connections between nodes through drag

**Implementation Details:**

1. Extend `TopologyCanvas` to support connection creation:
   ```tsx
   const onConnect = useCallback((connection: Connection) => {
     const newLink: TopologyLink = {
       id: `${connection.source}-${connection.target}`,
       sourceId: connection.source,
       targetId: connection.target,
       status: 'pending',
       policy: {
         bandwidth: '10Mbps',
         latency: '0ms',
         jitter: '0ms',
         packetLoss: '0%',
       },
     };
     setLinks((prev) => [...prev, newLink]);
   }, []);
   ```

2. Create `LinkCreationHandler`:
   ```typescript
   const handleLinkCreation = (sourceId: string, targetId: string) => {
     // Check if same connection already exists
     // Create default policy
     // Add to links state
   };
   ```

3. Support link deletion:
   ```typescript
   const handleKeyDown = useCallback((event: KeyboardEvent) => {
     if (event.key === 'Delete' || event.key === 'Backspace') {
       if (selectedLinkId) {
         setLinks((prev) => prev.filter((l) => l.id !== selectedLinkId));
       }
     }
   }, [selectedLinkId]);
   ```

**File List:**
- `frontend/src/components/topology/TopologyCanvas.tsx` (modify)
- `frontend/src/hooks/useLinkManagement.ts`
- `frontend/src/components/topology/TopologyCanvas.css` (update)

**Test Steps:**
1. Run `npm run test:run`
2. Add two nodes to canvas
3. Drag to create link
4. Verify link display
5. Delete link

---

#### LC-004: Link Configuration Panel - Link Configuration Panel Enhancement

**Goal:** Enhance link configuration panel to support full network simulation parameter configuration

**Implementation Details:**

1. Enhance existing `TrafficControlPanel`:
   ```tsx
   interface TrafficControlPanelProps {
     link: TopologyLink | null;
     onSave: (linkId: string, policy: TrafficPolicy) => void;
     onDelete: (linkId: string) => void;
     onClose: () => void;
   }
   ```

2. Add more parameters:
   - Priority
   - Queue Depth
   - Corruption Rate

3. Parameter formatting:
   ```typescript
   const formatBandwidth = (value: number): string => {
     if (value >= 1e9) return `${(value / 1e9).toFixed(1)}Gbps`;
     if (value >= 1e6) return `${(value / 1e6).toFixed(1)}Mbps`;
     if (value >= 1e3) return `${(value / 1e3).toFixed(1)}Kbps`;
     return `${value}bps`;
   };
   ```

**File List:**
- `frontend/src/components/TrafficControlPanel.tsx` (modify)
- `frontend/src/components/TrafficControlPanel.css` (update)
- `frontend/src/utils/policyFormatters.ts`

**Test Steps:**
1. Run `npm run test:run`
2. Create link
3. Click link to open configuration panel
4. Configure parameters
5. Save configuration

---

#### LC-005: Topology Editor Page - Topology Editor Page

**Goal:** Create dedicated topology editor page integrating all editing components

**Implementation Details:**

1. Page layout:
   ```
   ┌─────────────────────────────────────────────────────────┐
   │ [Node Palette] │ [Canvas] │ [Config Panel] │
   │ │ │ │
   │ 🚁 Drone │ ┌───┐ ┌───┐ │ Name: drones │
   │ 📡 Ground │ │ A │───│ B │ │ Image: nginx │
   │ 🔀 Gateway │ └───┘ └───┘ │ Replicas: 3 │
   │ 🖥️ Server │ │ Labels: ... │
   │ 💻 Client │ │ │
   │ │ │ [Save] [Export] │
   └─────────────────────────────────────────────────────────┘
   ```

2. Create `TopologyEditor` page:
   ```tsx
   interface TopologyEditorProps {
     topologyId?: string; // Pass when editing existing topology
     onSave: (topology: NetworkTopology) => void;
   }
   ```

3. Integrate sub-components:
   - NodePalette (left side)
   - TopologyCanvas (center)
   - NodeConfigPanel / TrafficControlPanel (right side)

**File List:**
- `frontend/src/pages/TopologyEditor.tsx`
- `frontend/src/pages/TopologyEditor.css`
- `frontend/src/App.tsx` (add route)

**Test Steps:**
1. Run `npm run test:run`
2. Navigate to /topologies/new
3. Verify page layout
4. Test complete editing flow
5. Screenshot verification

---

#### LC-006: Topology Save - Topology Save Feature

**Goal:** Save visually edited topology as CRD YAML format

**Implementation Details:**

1. Create conversion function:
   ```typescript
   const editorStateToCRD = (
     nodes: EditorNode[],
     links: EditorLink[]
   ): { topology: NetworkTopology; trafficControls: TrafficControl[] } => {
     // 1. Aggregate nodes into NodeGroups
     const nodeGroups = aggregateNodeGroups(nodes);
     
     // 2. Generate NetworkTopology CRD
     const topology: NetworkTopology = {
       apiVersion: 'simulation.kuro.io/v1alpha1',
       kind: 'NetworkTopology',
       metadata: { name: '...', namespace: 'default' },
       spec: { nodeGroups },
     };
     
     // 3. Generate TrafficControl CRDs
     const trafficControls = generateTrafficControls(links);
     
     return { topology, trafficControls };
   };
   ```

2. Create YAML preview dialog:
   ```tsx
   interface YamlPreviewDialogProps {
     topology: NetworkTopology;
     trafficControls: TrafficControl[];
     onConfirm: () => void;
     onCancel: () => void;
   }
   ```

**File List:**
- `frontend/src/utils/topologyConverter.ts`
- `frontend/src/components/topology/YamlPreviewDialog.tsx`
- `frontend/src/stores/editorStore.ts`

**Test Steps:**
1. Run `npm run test:run`
2. Create topology
3. Click save
4. Verify YAML format
5. Confirm save

---

### Phase 2: Advanced Features (Medium Priority)

#### LC-007: Node Group Management - Node Group Management

**Goal:** Support organizing multiple nodes into node groups

**Implementation Details:**
- Create NodeGroupPanel component
- Support multi-select nodes
- Support configuring replica count
- Support batch label configuration

---

#### LC-008: Topology Templates - Topology Template Library

**Goal:** Provide predefined topology templates

**Predefined Templates:**
1. **Drone Swarm** - 1 ground station + N drones
2. **IoT Network** - Gateway + multiple sensor nodes
3. **Microservices** - API gateway + multiple services
4. **Star Topology** - Central node + multiple edge nodes
5. **Mesh Network** - Fully connected network

---

#### LC-009: Real-time Validation - Real-time Validation

**Goal:** Real-time validation of topology configuration

**Validation Rules:**
1. Node name uniqueness
2. Required field check
3. IP address format validation
4. Image name format validation
5. Orphaned node warning

---

#### LC-010: Undo/Redo - Undo/Redo

**Goal:** Support undo and redo of edit operations

**Implementation Details:**
- Use Zustand's temporal middleware
- Support shortcuts Ctrl+Z / Ctrl+Y
- Support up to 50 history steps

---

## Development Order

Recommended development order:

```
Week 1: LC-001 (Node Palette) → LC-003 (Link Drawing)
Week 2: LC-002 (Node Config Panel) → LC-004 (Link Config Panel)
Week 3: LC-005 (Topology Editor Page) → LC-006 (Topology Save)
Week 4: LC-007 (Node Groups) → LC-008 (Templates)
Week 5: LC-009 (Validation) → LC-010 (Undo/Redo)
```

---

## Running Development Agent

```bash
# Start development loop
./scripts/run-agent-loop.sh

# Or use quick script
./scripts/kuro-test-quick.sh
```

---

## Notes

1. **The last step of each Feature must be testing**
   - Code test: `npm run test:run`
   - Browser test: Use MCP browser tools
   - Screenshot save: At least 2 screenshots

2. **Follow existing code style**
   - Use TypeScript
   - Use Zustand for state management
   - Use React Flow for topology visualization
   - Place components in `frontend/src/components/` directory

3. **Backend API Integration**
   - Currently using Mock API
   - Keep API interface consistent
   - Can seamlessly switch to real backend in the future

---

## Changelog

- 2026-02-18: Created low-code editor development plan, added 10 new features