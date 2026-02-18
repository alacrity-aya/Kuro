import yaml from 'js-yaml';
import type { Node, Edge } from 'reactflow';
import type {
  NetworkTopology,
  TrafficControl,
  NodeGroup,
  TrafficPolicy,
  NodeRole,
} from '../types/api';

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
    status: string;
    groupId: string;
    image?: string;
    resources?: {
      cpu?: string;
      memory?: string;
    };
    command?: string[];
    env?: Record<string, string>;
  };
  isSelected: boolean;
}

export interface EditorEdgeData {
  policy?: TrafficPolicy;
}

export interface ConversionResult {
  topology: NetworkTopology | null;
  trafficControls: TrafficControl[];
  errors: string[];
  warnings: string[];
}

export interface ConversionOptions {
  topologyName: string;
  namespace: string;
  labels?: Record<string, string>;
  annotations?: Record<string, string>;
}

// ============================================================================
// Default Values
// ============================================================================

const DEFAULT_IMAGES: Record<NodeRole, string> = {
  drone: 'nicolaka/netshoot',
  'ground-station': 'nicolaka/netshoot',
  gateway: 'nicolaka/netshoot',
  server: 'nginx:alpine',
  client: 'busybox',
  custom: 'busybox',
};

const DEFAULT_POLICY: TrafficPolicy = {
  bandwidth: '10Mbps',
  latency: '5ms',
  jitter: '1ms',
  packetLoss: '0.1%',
};

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Group nodes by their role and configuration to create NodeGroups
 */
function groupNodesForCRD(
  nodes: Node<EditorNodeData>[]
): Map<string, { config: NodeGroup; nodeIds: string[] }> {
  const groups = new Map<string, { config: NodeGroup; nodeIds: string[] }>();
  
  nodes.forEach((node) => {
    const { role, labels, image, resources } = node.data.node;
    
    // Create a unique key for grouping
    // Group by role + image + resources (same config = same group)
    const imageStr = image || DEFAULT_IMAGES[role];
    const resourcesStr = resources ? JSON.stringify(resources) : '';
    const groupKey = `${role}:${imageStr}:${resourcesStr}`;
    
    if (!groups.has(groupKey)) {
      // Merge labels, removing 'role' if it's just the role name
      const groupLabels: Record<string, string> = { role };
      Object.entries(labels || {}).forEach(([k, v]) => {
        if (k !== 'role') {
          groupLabels[k] = v;
        }
      });
      
      groups.set(groupKey, {
        config: {
          name: `${role}-group`,
          replicas: 0,
          image: imageStr,
          labels: groupLabels,
          resources: resources || undefined,
        },
        nodeIds: [],
      });
    }
    
    const group = groups.get(groupKey)!;
    group.config.replicas += 1;
    group.nodeIds.push(node.id);
  });
  
  return groups;
}

/**
 * Group edges by their source/target role combinations to create TrafficControls
 */
function groupEdgesForCRD(
  edges: Edge<EditorEdgeData>[],
  nodes: Node<EditorNodeData>[]
): Map<string, { config: TrafficControl; sourceNodes: Set<string>; targetNodes: Set<string> }> {
  const controls = new Map<string, { 
    config: TrafficControl; 
    sourceNodes: Set<string>; 
    targetNodes: Set<string> 
  }>();
  
  // Build node lookup map
  const nodeMap = new Map<string, Node<EditorNodeData>>();
  nodes.forEach((node) => nodeMap.set(node.id, node));
  
  edges.forEach((edge) => {
    const sourceNode = nodeMap.get(edge.source);
    const targetNode = nodeMap.get(edge.target);
    
    if (!sourceNode || !targetNode) {
      return;
    }
    
    const sourceRole = sourceNode.data.node.role;
    const targetRole = targetNode.data.node.role;
    const policy = edge.data?.policy || DEFAULT_POLICY;
    
    // Create a key for this source->target combination
    const controlKey = `${sourceRole}->${targetRole}`;
    
    if (!controls.has(controlKey)) {
      controls.set(controlKey, {
        config: {
          apiVersion: 'simulation.kuro.io/v1alpha1',
          kind: 'TrafficControl',
          metadata: {
            name: `tc-${sourceRole}-to-${targetRole}`,
            namespace: 'default',
            uid: '',
            creationTimestamp: new Date().toISOString(),
          },
          spec: {
            source: {
              matchLabels: { role: sourceRole },
            },
            destination: {
              matchLabels: { role: targetRole },
            },
            policy: { ...policy },
          },
        },
        sourceNodes: new Set(),
        targetNodes: new Set(),
      });
    }
    
    const control = controls.get(controlKey)!;
    control.sourceNodes.add(edge.source);
    control.targetNodes.add(edge.target);
  });
  
  return controls;
}

/**
 * Validate editor state before conversion
 */
function validateEditorState(
  nodes: Node<EditorNodeData>[],
  edges: Edge<EditorEdgeData>[],
  options: ConversionOptions
): { errors: string[]; warnings: string[] } {
  const errors: string[] = [];
  const warnings: string[] = [];
  
  // Check topology name
  if (!options.topologyName) {
    errors.push('Topology name is required');
  } else if (!/^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/.test(options.topologyName)) {
    errors.push('Topology name must be lowercase alphanumeric with hyphens');
  }
  
  // Check nodes
  if (nodes.length === 0) {
    errors.push('At least one node is required');
  }
  
  // Check for isolated nodes (no connections)
  const connectedNodeIds = new Set<string>();
  edges.forEach((edge) => {
    connectedNodeIds.add(edge.source);
    connectedNodeIds.add(edge.target);
  });
  
  nodes.forEach((node) => {
    if (!connectedNodeIds.has(node.id)) {
      warnings.push(`Node "${node.data.node.name}" has no connections`);
    }
  });
  
  // Check for duplicate node names
  const nodeNames = new Set<string>();
  nodes.forEach((node) => {
    const name = node.data.node.name;
    if (nodeNames.has(name)) {
      warnings.push(`Duplicate node name: "${name}"`);
    }
    nodeNames.add(name);
  });
  
  return { errors, warnings };
}

// ============================================================================
// Main Conversion Functions
// ============================================================================

/**
 * Convert editor state to NetworkTopology CRD and TrafficControl CRDs
 */
export function editorStateToCRD(
  nodes: Node<EditorNodeData>[],
  edges: Edge<EditorEdgeData>[],
  options: ConversionOptions
): ConversionResult {
  const { errors, warnings } = validateEditorState(nodes, edges, options);
  
  if (errors.length > 0) {
    return {
      topology: null,
      trafficControls: [],
      errors,
      warnings,
    };
  }
  
  // Create NodeGroups from nodes
  const nodeGroupMap = groupNodesForCRD(nodes);
  const nodeGroups: NodeGroup[] = Array.from(nodeGroupMap.values()).map((g) => g.config);
  
  // Create NetworkTopology CRD
  const topology: NetworkTopology = {
    apiVersion: 'simulation.kuro.io/v1alpha1',
    kind: 'NetworkTopology',
    metadata: {
      name: options.topologyName,
      namespace: options.namespace,
      uid: '',
      creationTimestamp: new Date().toISOString(),
      labels: options.labels,
      annotations: options.annotations,
    },
    spec: {
      nodeGroups,
    },
  };
  
  // Create TrafficControl CRDs from edges
  const trafficControlMap = groupEdgesForCRD(edges, nodes);
  const trafficControls: TrafficControl[] = Array.from(trafficControlMap.values())
    .map((tc) => ({
      ...tc.config,
      metadata: {
        ...tc.config.metadata,
        namespace: options.namespace,
      },
    }));
  
  return {
    topology,
    trafficControls,
    errors: [],
    warnings,
  };
}

/**
 * Generate YAML string from conversion result
 */
export function generateYamlOutput(result: ConversionResult): string {
  const documents: unknown[] = [];
  
  if (result.topology) {
    documents.push(result.topology);
  }
  
  result.trafficControls.forEach((tc) => {
    documents.push(tc);
  });
  
  // Use yaml.dump with multiple documents
  return documents
    .map((doc) => yaml.dump(doc, {
      indent: 2,
      lineWidth: -1,
      noRefs: true,
      sortKeys: false,
    }))
    .join('---\n');
}

/**
 * Convert and generate YAML in one step
 */
export function editorStateToYaml(
  nodes: Node<EditorNodeData>[],
  edges: Edge<EditorEdgeData>[],
  options: ConversionOptions
): { yaml: string; errors: string[]; warnings: string[] } {
  const result = editorStateToCRD(nodes, edges, options);
  
  if (result.errors.length > 0) {
    return {
      yaml: '',
      errors: result.errors,
      warnings: result.warnings,
    };
  }
  
  const yamlContent = generateYamlOutput(result);
  
  return {
    yaml: yamlContent,
    errors: [],
    warnings: result.warnings,
  };
}

/**
 * Download YAML file
 */
export function downloadYaml(yamlContent: string, filename: string): void {
  const blob = new Blob([yamlContent], { type: 'text/yaml' });
  const url = URL.createObjectURL(blob);
  
  const link = document.createElement('a');
  link.href = url;
  link.download = filename.endsWith('.yaml') ? filename : `${filename}.yaml`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

/**
 * Copy YAML to clipboard
 */
export async function copyYamlToClipboard(yamlContent: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(yamlContent);
    return true;
  } catch {
    return false;
  }
}
