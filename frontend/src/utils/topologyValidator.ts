import type { Node, Edge } from 'reactflow';
import type { NodeRole, TrafficPolicy } from '../types/api';

// ============================================================================
// Types
// ============================================================================

export interface ValidationIssue {
  id: string;
  type: 'error' | 'warning' | 'info';
  message: string;
  nodeId?: string;
  edgeId?: string;
  field?: string;
  suggestion?: string;
}

export interface ValidationResult {
  isValid: boolean;
  hasErrors: boolean;
  hasWarnings: boolean;
  issues: ValidationIssue[];
  summary: {
    totalNodes: number;
    totalEdges: number;
    connectedNodes: number;
    isolatedNodes: number;
    duplicateNames: string[];
  };
}

export interface ValidationOptions {
  checkIsolatedNodes?: boolean;
  checkDuplicateNames?: boolean;
  checkInvalidPolicies?: boolean;
  checkNameFormat?: boolean;
  minNodes?: number;
  maxNodes?: number;
}

// ============================================================================
// Constants
// ============================================================================

const VALID_NAME_REGEX = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

const BANDWIDTH_REGEX = /^(\d+(?:\.\d+)?)(Kbps|Mbps|Gbps|kbps|mbps|gbps)$/i;
const LATENCY_REGEX = /^(\d+(?:\.\d+)?)(ms|us|s)$/i;
const PACKET_LOSS_REGEX = /^(\d+(?:\.\d+)?)(%)?$/i;

// ============================================================================
// Validation Helper Functions
// ============================================================================

/**
 * Validate bandwidth format
 */
function isValidBandwidth(value: string): boolean {
  return BANDWIDTH_REGEX.test(value);
}

/**
 * Validate latency format
 */
function isValidLatency(value: string): boolean {
  return LATENCY_REGEX.test(value);
}

/**
 * Validate packet loss format
 */
function isValidPacketLoss(value: string): boolean {
  if (!PACKET_LOSS_REGEX.test(value)) return false;
  const match = value.match(PACKET_LOSS_REGEX);
  if (!match) return false;
  const num = parseFloat(match[1]);
  return num >= 0 && num <= 100;
}

/**
 * Validate a TrafficPolicy
 */
function validatePolicy(policy: TrafficPolicy | undefined, edgeId: string): ValidationIssue[] {
  const issues: ValidationIssue[] = [];
  
  if (!policy) return issues;
  
  if (policy.bandwidth && !isValidBandwidth(policy.bandwidth)) {
    issues.push({
      id: `invalid-bandwidth-${edgeId}`,
      type: 'warning',
      message: `Invalid bandwidth format: "${policy.bandwidth}". Expected format: "10Mbps", "1Gbps"`,
      edgeId,
      field: 'bandwidth',
      suggestion: 'Use format like "10Mbps", "100Mbps", "1Gbps"',
    });
  }
  
  if (policy.latency && !isValidLatency(policy.latency)) {
    issues.push({
      id: `invalid-latency-${edgeId}`,
      type: 'warning',
      message: `Invalid latency format: "${policy.latency}". Expected format: "10ms", "100us"`,
      edgeId,
      field: 'latency',
      suggestion: 'Use format like "5ms", "10ms", "100us"',
    });
  }
  
  if (policy.jitter && !isValidLatency(policy.jitter)) {
    issues.push({
      id: `invalid-jitter-${edgeId}`,
      type: 'warning',
      message: `Invalid jitter format: "${policy.jitter}". Expected format: "1ms", "10us"`,
      edgeId,
      field: 'jitter',
      suggestion: 'Use format like "1ms", "5ms"',
    });
  }
  
  if (policy.packetLoss && !isValidPacketLoss(policy.packetLoss)) {
    issues.push({
      id: `invalid-packetloss-${edgeId}`,
      type: 'warning',
      message: `Invalid packet loss format: "${policy.packetLoss}". Expected format: "0.1%", "1%"`,
      edgeId,
      field: 'packetLoss',
      suggestion: 'Use percentage like "0.1%", "1%", or just "0.5"',
    });
  }
  
  return issues;
}

/**
 * Validate node name format (Kubernetes naming conventions)
 */
function validateNodeName(name: string, nodeId: string): ValidationIssue | null {
  if (!name || name.trim() === '') {
    return {
      id: `empty-name-${nodeId}`,
      type: 'error',
      message: 'Node name is required',
      nodeId,
      field: 'name',
    };
  }
  
  if (!VALID_NAME_REGEX.test(name)) {
    return {
      id: `invalid-name-${nodeId}`,
      type: 'warning',
      message: `Node name "${name}" may not be valid for Kubernetes. Use lowercase alphanumeric and hyphens.`,
      nodeId,
      field: 'name',
      suggestion: 'Use lowercase letters, numbers, and hyphens only',
    };
  }
  
  if (name.length > 63) {
    return {
      id: `name-too-long-${nodeId}`,
      type: 'warning',
      message: `Node name "${name}" exceeds 63 character limit for Kubernetes labels`,
      nodeId,
      field: 'name',
    };
  }
  
  return null;
}

// ============================================================================
// Main Validation Function
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
  };
  isSelected: boolean;
}

export interface EditorEdgeData {
  policy?: TrafficPolicy;
}

/**
 * Validate entire topology state
 */
export function validateTopology(
  nodes: Node<EditorNodeData>[],
  edges: Edge<EditorEdgeData>[],
  topologyName: string = '',
  options: ValidationOptions = {}
): ValidationResult {
  const {
    checkIsolatedNodes = true,
    checkDuplicateNames = true,
    checkInvalidPolicies = true,
    checkNameFormat = true,
    minNodes = 1,
    maxNodes = 100,
  } = options;

  const issues: ValidationIssue[] = [];

  // Track statistics
  const connectedNodeIds = new Set<string>();
  edges.forEach((edge) => {
    connectedNodeIds.add(edge.source);
    connectedNodeIds.add(edge.target);
  });

  const isolatedNodeIds: string[] = [];
  const duplicateNames: string[] = [];
  const nameCounts = new Map<string, number>();

  // ========================================
  // Validate topology name
  // ========================================
  if (checkNameFormat && topologyName) {
    if (!VALID_NAME_REGEX.test(topologyName)) {
      issues.push({
        id: 'invalid-topology-name',
        type: 'error',
        message: `Topology name "${topologyName}" is not valid. Use lowercase alphanumeric and hyphens.`,
        field: 'topologyName',
        suggestion: 'Use format like "my-topology", "drone-swarm-v1"',
      });
    }
  }

  // ========================================
  // Validate node count
  // ========================================
  if (nodes.length < minNodes) {
    issues.push({
      id: 'insufficient-nodes',
      type: 'error',
      message: `At least ${minNodes} node(s) required. Current: ${nodes.length}`,
    });
  }

  if (nodes.length > maxNodes) {
    issues.push({
      id: 'too-many-nodes',
      type: 'warning',
      message: `Topology has ${nodes.length} nodes. Consider splitting into smaller topologies.`,
    });
  }

  // ========================================
  // Validate each node
  // ========================================
  nodes.forEach((node) => {
    const nodeData = node.data.node;

    // Check for isolated nodes
    if (!connectedNodeIds.has(node.id)) {
      isolatedNodeIds.push(node.id);
    }

    // Check name format
    if (checkNameFormat) {
      const nameIssue = validateNodeName(nodeData.name, node.id);
      if (nameIssue) {
        issues.push(nameIssue);
      }
    }

    // Track name duplicates
    const name = nodeData.name;
    nameCounts.set(name, (nameCounts.get(name) || 0) + 1);
  });

  // ========================================
  // Report duplicate names
  // ========================================
  if (checkDuplicateNames) {
    nameCounts.forEach((count, name) => {
      if (count > 1) {
        duplicateNames.push(name);
        issues.push({
          id: `duplicate-name-${name}`,
          type: 'warning',
          message: `Duplicate node name: "${name}" (${count} nodes)`,
          field: 'name',
          suggestion: 'Use unique names to avoid confusion',
        });
      }
    });
  }

  // ========================================
  // Report isolated nodes
  // ========================================
  if (checkIsolatedNodes && isolatedNodeIds.length > 0) {
    isolatedNodeIds.forEach((nodeId) => {
      const node = nodes.find((n) => n.id === nodeId);
      const nodeName = node?.data?.node?.name || nodeId;
      issues.push({
        id: `isolated-node-${nodeId}`,
        type: 'warning',
        message: `Node "${nodeName}" has no connections`,
        nodeId,
        suggestion: 'Connect this node to other nodes in the topology',
      });
    });
  }

  // ========================================
  // Validate each edge/policy
  // ========================================
  if (checkInvalidPolicies) {
    edges.forEach((edge) => {
      const policyIssues = validatePolicy(edge.data?.policy, edge.id);
      issues.push(...policyIssues);
    });
  }

  // ========================================
  // Calculate result
  // ========================================
  const hasErrors = issues.some((i) => i.type === 'error');
  const hasWarnings = issues.some((i) => i.type === 'warning');

  return {
    isValid: !hasErrors,
    hasErrors,
    hasWarnings,
    issues,
    summary: {
      totalNodes: nodes.length,
      totalEdges: edges.length,
      connectedNodes: connectedNodeIds.size,
      isolatedNodes: isolatedNodeIds.length,
      duplicateNames,
    },
  };
}

/**
 * Quick check if topology has any critical errors
 */
export function hasValidationErrors(
  nodes: Node<EditorNodeData>[],
  _edges: Edge<EditorEdgeData>[],
  topologyName: string = ''
): boolean {
  // Quick checks without full validation
  if (nodes.length === 0) return true;
  if (topologyName && !VALID_NAME_REGEX.test(topologyName)) return true;
  
  // Check for empty node names
  for (const node of nodes) {
    if (!node.data?.node?.name || node.data.node.name.trim() === '') {
      return true;
    }
  }
  
  return false;
}

/**
 * Get issues for a specific node
 */
export function getNodeIssues(
  validationResult: ValidationResult,
  nodeId: string
): ValidationIssue[] {
  return validationResult.issues.filter((issue) => issue.nodeId === nodeId);
}

/**
 * Get issues for a specific edge
 */
export function getEdgeIssues(
  validationResult: ValidationResult,
  edgeId: string
): ValidationIssue[] {
  return validationResult.issues.filter((issue) => issue.edgeId === edgeId);
}
