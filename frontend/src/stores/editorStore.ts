import { create } from 'zustand';
import type { Node, Edge } from 'reactflow';
import type { TrafficPolicy, NodeRole } from '../types/api';

// ============================================================================
// Types
// ============================================================================

export interface EditorNodeData {
  node: {
    id: string;
    name: string;
    role: NodeRole;
    ip: string;
    labels: Record<string, string>;
    status: 'running' | 'pending' | 'failed' | 'unknown';
    groupId: string;
    image?: string;
    resources?: {
      cpu?: string;
      memory?: string;
    };
    x?: number;
    y?: number;
  };
  isSelected: boolean;
}

export interface EditorEdgeData {
  policy?: TrafficPolicy;
}

export interface NodeGroupConfig {
  name: string;
  role: NodeRole;
  image: string;
  replicas: number;
  labels: Record<string, string>;
  resources?: {
    cpu?: string;
    memory?: string;
  };
  nodeIds: string[];
}

export interface TrafficControlConfig {
  name: string;
  sourceSelector: Record<string, string>;
  targetSelector: Record<string, string>;
  policy: TrafficPolicy;
  sourceNodes: string[];
  targetNodes: string[];
}

interface EditorState {
  // Editor metadata
  topologyName: string;
  namespace: string;
  
  // Nodes and edges
  nodes: Node<EditorNodeData>[];
  edges: Edge<EditorEdgeData>[];
  
  // Derived data (computed from nodes/edges)
  nodeGroups: NodeGroupConfig[];
  trafficControls: TrafficControlConfig[];
  
  // UI State
  isDirty: boolean;
  isPreviewOpen: boolean;
  previewYaml: string;
  
  // Actions - Metadata
  setTopologyName: (name: string) => void;
  setNamespace: (namespace: string) => void;
  
  // Actions - Nodes/Edges
  setNodes: (nodes: Node<EditorNodeData>[]) => void;
  setEdges: (edges: Edge<EditorEdgeData>[]) => void;
  addNode: (node: Node<EditorNodeData>) => void;
  removeNode: (nodeId: string) => void;
  updateNode: (nodeId: string, updates: Partial<EditorNodeData['node']>) => void;
  addEdge: (edge: Edge<EditorEdgeData>) => void;
  removeEdge: (edgeId: string) => void;
  updateEdgePolicy: (edgeId: string, policy: TrafficPolicy) => void;
  
  // Actions - Derived
  recalculateGroups: () => void;
  recalculateTrafficControls: () => void;
  
  // Actions - UI
  openPreview: (yaml: string) => void;
  closePreview: () => void;
  markClean: () => void;
  
  // Actions - Reset
  reset: () => void;
  
  // Actions - Import
  loadFromData: (nodes: Node<EditorNodeData>[], edges: Edge<EditorEdgeData>[]) => void;
}

// ============================================================================
// Initial State
// ============================================================================

const initialState = {
  topologyName: '',
  namespace: 'default',
  nodes: [] as Node<EditorNodeData>[],
  edges: [] as Edge<EditorEdgeData>[],
  nodeGroups: [] as NodeGroupConfig[],
  trafficControls: [] as TrafficControlConfig[],
  isDirty: false,
  isPreviewOpen: false,
  previewYaml: '',
};

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Group nodes by their role and image to create NodeGroups
 */
function groupNodesByConfig(nodes: Node<EditorNodeData>[]): NodeGroupConfig[] {
  const groups = new Map<string, NodeGroupConfig>();
  
  nodes.forEach((node) => {
    const { role, labels, image } = node.data.node;
    // Create a group key based on role and image
    const groupKey = `${role}:${image || 'default'}`;
    
    if (!groups.has(groupKey)) {
      groups.set(groupKey, {
        name: `${role}-group`,
        role,
        image: image || getDefaultImage(role),
        replicas: 0,
        labels: { role, ...labels },
        nodeIds: [],
      });
    }
    
    const group = groups.get(groupKey)!;
    group.replicas += 1;
    group.nodeIds.push(node.id);
  });
  
  return Array.from(groups.values());
}

/**
 * Group edges by their source/target role combinations to create TrafficControls
 */
function groupEdgesByPolicy(
  edges: Edge<EditorEdgeData>[],
  nodes: Node<EditorNodeData>[]
): TrafficControlConfig[] {
  const controls = new Map<string, TrafficControlConfig>();
  
  // Build a node id to node map
  const nodeMap = new Map<string, Node<EditorNodeData>>();
  nodes.forEach((node) => nodeMap.set(node.id, node));
  
  edges.forEach((edge) => {
    const sourceNode = nodeMap.get(edge.source);
    const targetNode = nodeMap.get(edge.target);
    
    if (!sourceNode || !targetNode) return;
    
    const sourceRole = sourceNode.data.node.role;
    const targetRole = targetNode.data.node.role;
    const policy = edge.data?.policy;
    
    // Create a control key based on source/target roles
    const controlKey = `${sourceRole}:${targetRole}`;
    
    if (!controls.has(controlKey)) {
      controls.set(controlKey, {
        name: `tc-${sourceRole}-to-${targetRole}`,
        sourceSelector: { role: sourceRole },
        targetSelector: { role: targetRole },
        policy: policy || getDefaultPolicy(),
        sourceNodes: [],
        targetNodes: [],
      });
    }
    
    const control = controls.get(controlKey)!;
    control.sourceNodes.push(edge.source);
    control.targetNodes.push(edge.target);
    
    // Merge policies (use the last one if different, or keep default)
    if (policy && control.policy !== policy) {
      control.policy = policy;
    }
  });
  
  return Array.from(controls.values());
}

function getDefaultImage(role: NodeRole): string {
  const defaults: Record<NodeRole, string> = {
    drone: 'nicolaka/netshoot',
    'ground-station': 'nicolaka/netshoot',
    gateway: 'nicolaka/netshoot',
    server: 'nginx:alpine',
    client: 'busybox',
    custom: 'busybox',
  };
  return defaults[role] || 'busybox';
}

function getDefaultPolicy(): TrafficPolicy {
  return {
    bandwidth: '10Mbps',
    latency: '5ms',
    jitter: '1ms',
    packetLoss: '0.1%',
  };
}

// ============================================================================
// Store Implementation
// ============================================================================

export const useEditorStore = create<EditorState>()((set, get) => ({
  ...initialState,
  
  // ========================================================================
  // Metadata Actions
  // ========================================================================
  
  setTopologyName: (name) => {
    set({ topologyName: name, isDirty: true });
  },
  
  setNamespace: (namespace) => {
    set({ namespace, isDirty: true });
  },
  
  // ========================================================================
  // Node/Edge Actions
  // ========================================================================
  
  setNodes: (nodes) => {
    set({ nodes, isDirty: true });
    get().recalculateGroups();
  },
  
  setEdges: (edges) => {
    set({ edges, isDirty: true });
    get().recalculateTrafficControls();
  },
  
  addNode: (node) => {
    set((state) => ({
      nodes: [...state.nodes, node],
      isDirty: true,
    }));
    get().recalculateGroups();
  },
  
  removeNode: (nodeId) => {
    set((state) => ({
      nodes: state.nodes.filter((n) => n.id !== nodeId),
      edges: state.edges.filter((e) => e.source !== nodeId && e.target !== nodeId),
      isDirty: true,
    }));
    get().recalculateGroups();
    get().recalculateTrafficControls();
  },
  
  updateNode: (nodeId, updates) => {
    set((state) => ({
      nodes: state.nodes.map((n) =>
        n.id === nodeId
          ? { ...n, data: { ...n.data, node: { ...n.data.node, ...updates } } }
          : n
      ),
      isDirty: true,
    }));
    get().recalculateGroups();
  },
  
  addEdge: (edge) => {
    set((state) => ({
      edges: [...state.edges, edge],
      isDirty: true,
    }));
    get().recalculateTrafficControls();
  },
  
  removeEdge: (edgeId) => {
    set((state) => ({
      edges: state.edges.filter((e) => e.id !== edgeId),
      isDirty: true,
    }));
    get().recalculateTrafficControls();
  },
  
  updateEdgePolicy: (edgeId, policy) => {
    set((state) => ({
      edges: state.edges.map((e) =>
        e.id === edgeId
          ? { ...e, data: { ...e.data, policy } }
          : e
      ),
      isDirty: true,
    }));
    get().recalculateTrafficControls();
  },
  
  // ========================================================================
  // Derived Actions
  // ========================================================================
  
  recalculateGroups: () => {
    const { nodes } = get();
    const nodeGroups = groupNodesByConfig(nodes);
    set({ nodeGroups });
  },
  
  recalculateTrafficControls: () => {
    const { edges, nodes } = get();
    const trafficControls = groupEdgesByPolicy(edges, nodes);
    set({ trafficControls });
  },
  
  // ========================================================================
  // UI Actions
  // ========================================================================
  
  openPreview: (yaml) => {
    set({ isPreviewOpen: true, previewYaml: yaml });
  },
  
  closePreview: () => {
    set({ isPreviewOpen: false });
  },
  
  markClean: () => {
    set({ isDirty: false });
  },
  
  // ========================================================================
  // Reset
  // ========================================================================
  
  reset: () => {
    set(initialState);
  },
  
  // ========================================================================
  // Import
  // ========================================================================
  
  loadFromData: (nodes, edges) => {
    set({ nodes, edges, isDirty: false });
    get().recalculateGroups();
    get().recalculateTrafficControls();
  },
}));

// ============================================================================
// Convenience Hooks
// ============================================================================

/**
 * Hook for checking if there are unsaved changes
 */
export function useHasUnsavedChanges() {
  return useEditorStore((state) => state.isDirty);
}

/**
 * Hook for getting summary stats
 */
export function useEditorStats() {
  const nodes = useEditorStore((state) => state.nodes);
  const edges = useEditorStore((state) => state.edges);
  const nodeGroups = useEditorStore((state) => state.nodeGroups);
  const trafficControls = useEditorStore((state) => state.trafficControls);
  
  return {
    totalNodes: nodes.length,
    totalEdges: edges.length,
    totalGroups: nodeGroups.length,
    totalTrafficControls: trafficControls.length,
  };
}
