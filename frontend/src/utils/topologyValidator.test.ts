import { describe, it, expect } from 'vitest';
import {
  validateTopology,
  hasValidationErrors,
  getNodeIssues,
  getEdgeIssues,
  type EditorNodeData,
  type EditorEdgeData,
} from './topologyValidator';
import type { Node, Edge } from 'reactflow';
import type { NodeRole, TrafficPolicy } from '../types/api';

// Helper to create a mock node
function createMockNode(
  id: string,
  name: string,
  role: NodeRole = 'drone',
  overrides: Partial<EditorNodeData['node']> = {}
): Node<EditorNodeData> {
  return {
    id,
    type: 'custom',
    position: { x: 0, y: 0 },
    data: {
      node: {
        id,
        name,
        role,
        ip: `10.0.0.${id.replace('node-', '')}`,
        labels: { role },
        status: 'pending',
        groupId: '',
        ...overrides,
      },
      isSelected: false,
    },
  };
}

// Helper to create a mock edge
function createMockEdge(
  id: string,
  source: string,
  target: string,
  policy?: TrafficPolicy
): Edge<EditorEdgeData> {
  return {
    id,
    source,
    target,
    type: 'smoothstep',
    data: {
      policy,
    },
  };
}

describe('validateTopology', () => {
  describe('basic validation', () => {
    it('returns valid for empty topology with no min nodes requirement', () => {
      const result = validateTopology([], [], '', { minNodes: 0 });
      
      expect(result.isValid).toBe(true);
      expect(result.hasErrors).toBe(false);
      expect(result.issues).toHaveLength(0);
    });

    it('returns error when nodes count is below minimum', () => {
      const result = validateTopology([], [], '', { minNodes: 1 });
      
      expect(result.isValid).toBe(false);
      expect(result.hasErrors).toBe(true);
      expect(result.issues[0].message).toContain('At least 1 node');
    });

    it('returns warning when nodes count exceeds maximum', () => {
      const nodes = Array.from({ length: 101 }, (_, i) =>
        createMockNode(`node-${i}`, `node-${i}`)
      );
      
      const result = validateTopology(nodes, [], '', { maxNodes: 100 });
      
      expect(result.hasWarnings).toBe(true);
      expect(result.issues[0].message).toContain('101 nodes');
    });
  });

  describe('topology name validation', () => {
    it('accepts valid topology names', () => {
      const node = createMockNode('node-1', 'test-node');
      const result = validateTopology([node], [], 'my-topology');
      
      // No error for topology name
      const nameErrors = result.issues.filter((i) => i.field === 'topologyName');
      expect(nameErrors).toHaveLength(0);
    });

    it('rejects invalid topology names', () => {
      const node = createMockNode('node-1', 'test-node');
      const result = validateTopology([node], [], 'Invalid_Name!');
      
      expect(result.hasErrors).toBe(true);
      expect(result.issues[0].message).toContain('not valid');
    });

    it('accepts empty topology name', () => {
      const node = createMockNode('node-1', 'test-node');
      const result = validateTopology([node], [], '');
      
      // No error for empty name
      const nameErrors = result.issues.filter((i) => i.field === 'topologyName');
      expect(nameErrors).toHaveLength(0);
    });
  });

  describe('node name validation', () => {
    it('returns error for empty node name', () => {
      const node = createMockNode('node-1', '');
      const result = validateTopology([node], [], '', { checkNameFormat: true });
      
      expect(result.hasErrors).toBe(true);
      expect(result.issues[0].message).toContain('name is required');
    });

    it('returns warning for invalid Kubernetes name format', () => {
      const node = createMockNode('node-1', 'Invalid_Node_Name');
      const result = validateTopology([node], [], '', { checkNameFormat: true });
      
      expect(result.hasWarnings).toBe(true);
      expect(result.issues[0].message).toContain('may not be valid');
    });

    it('returns warning for name exceeding 63 characters', () => {
      const longName = 'a'.repeat(64);
      const node = createMockNode('node-1', longName);
      const result = validateTopology([node], [], '', { checkNameFormat: true });
      
      expect(result.hasWarnings).toBe(true);
      expect(result.issues[0].message).toContain('63 character');
    });

    it('accepts valid node names', () => {
      const node = createMockNode('node-1', 'my-drone-1');
      const result = validateTopology([node], [], '', { checkNameFormat: true });
      
      const nameIssues = result.issues.filter((i) => i.field === 'name');
      expect(nameIssues).toHaveLength(0);
    });
  });

  describe('isolated nodes detection', () => {
    it('detects isolated nodes', () => {
      const node1 = createMockNode('node-1', 'drone-1');
      const node2 = createMockNode('node-2', 'drone-2');
      const edge = createMockEdge('edge-1', 'node-1', 'node-2');
      
      const node3 = createMockNode('node-3', 'isolated-drone');
      
      const result = validateTopology([node1, node2, node3], [edge], '', {
        checkIsolatedNodes: true,
      });
      
      expect(result.hasWarnings).toBe(true);
      expect(result.issues.some((i) => i.message.includes('isolated-drone'))).toBe(true);
      expect(result.summary.isolatedNodes).toBe(1);
    });

    it('does not report isolated nodes when disabled', () => {
      const node = createMockNode('node-1', 'isolated-node');
      const result = validateTopology([node], [], '', { checkIsolatedNodes: false });
      
      expect(result.issues.some((i) => i.message.includes('no connections'))).toBe(false);
    });
  });

  describe('duplicate names detection', () => {
    it('detects duplicate node names', () => {
      const node1 = createMockNode('node-1', 'same-name');
      const node2 = createMockNode('node-2', 'same-name');
      
      const result = validateTopology([node1, node2], [], '', {
        checkDuplicateNames: true,
      });
      
      expect(result.hasWarnings).toBe(true);
      expect(result.issues[0].message).toContain('Duplicate node name');
      expect(result.summary.duplicateNames).toContain('same-name');
    });

    it('does not report duplicates when disabled', () => {
      const node1 = createMockNode('node-1', 'same-name');
      const node2 = createMockNode('node-2', 'same-name');
      
      const result = validateTopology([node1, node2], [], '', {
        checkDuplicateNames: false,
      });
      
      expect(result.issues.some((i) => i.message.includes('Duplicate'))).toBe(false);
    });
  });

  describe('policy validation', () => {
    it('validates correct bandwidth format', () => {
      const node1 = createMockNode('node-1', 'drone-1');
      const node2 = createMockNode('node-2', 'drone-2');
      const edge = createMockEdge('edge-1', 'node-1', 'node-2', {
        bandwidth: '10Mbps',
        latency: '5ms',
        jitter: '1ms',
        packetLoss: '0.1%',
      });
      
      const result = validateTopology([node1, node2], [edge], '', {
        checkInvalidPolicies: true,
      });
      
      const policyIssues = result.issues.filter((i) => i.edgeId === 'edge-1');
      expect(policyIssues).toHaveLength(0);
    });

    it('warns on invalid bandwidth format', () => {
      const node1 = createMockNode('node-1', 'drone-1');
      const node2 = createMockNode('node-2', 'drone-2');
      const edge = createMockEdge('edge-1', 'node-1', 'node-2', {
        bandwidth: 'invalid',
        latency: '5ms',
        jitter: '1ms',
        packetLoss: '0.1%',
      });
      
      const result = validateTopology([node1, node2], [edge], '', {
        checkInvalidPolicies: true,
      });
      
      expect(result.hasWarnings).toBe(true);
      expect(result.issues[0].message).toContain('Invalid bandwidth format');
    });

    it('warns on invalid latency format', () => {
      const node1 = createMockNode('node-1', 'drone-1');
      const node2 = createMockNode('node-2', 'drone-2');
      const edge = createMockEdge('edge-1', 'node-1', 'node-2', {
        bandwidth: '10Mbps',
        latency: 'invalid',
        jitter: '1ms',
        packetLoss: '0.1%',
      });
      
      const result = validateTopology([node1, node2], [edge], '', {
        checkInvalidPolicies: true,
      });
      
      expect(result.hasWarnings).toBe(true);
      expect(result.issues[0].message).toContain('Invalid latency format');
    });

    it('warns on invalid packet loss format', () => {
      const node1 = createMockNode('node-1', 'drone-1');
      const node2 = createMockNode('node-2', 'drone-2');
      const edge = createMockEdge('edge-1', 'node-1', 'node-2', {
        bandwidth: '10Mbps',
        latency: '5ms',
        jitter: '1ms',
        packetLoss: '150%', // Invalid: > 100%
      });
      
      const result = validateTopology([node1, node2], [edge], '', {
        checkInvalidPolicies: true,
      });
      
      expect(result.hasWarnings).toBe(true);
      expect(result.issues[0].message).toContain('Invalid packet loss');
    });
  });

  describe('summary calculation', () => {
    it('calculates correct summary', () => {
      const node1 = createMockNode('node-1', 'drone-1');
      const node2 = createMockNode('node-2', 'drone-2');
      const node3 = createMockNode('node-3', 'drone-3');
      const edge = createMockEdge('edge-1', 'node-1', 'node-2');
      
      const result = validateTopology([node1, node2, node3], [edge], '');
      
      expect(result.summary.totalNodes).toBe(3);
      expect(result.summary.totalEdges).toBe(1);
      expect(result.summary.connectedNodes).toBe(2);
      expect(result.summary.isolatedNodes).toBe(1);
    });
  });
});

describe('hasValidationErrors', () => {
  it('returns true for empty topology', () => {
    expect(hasValidationErrors([], [], '')).toBe(true);
  });

  it('returns true for invalid topology name', () => {
    const node = createMockNode('node-1', 'test');
    expect(hasValidationErrors([node], [], 'Invalid!')).toBe(true);
  });

  it('returns true for empty node name', () => {
    const node = createMockNode('node-1', '');
    expect(hasValidationErrors([node], [], 'test')).toBe(true);
  });

  it('returns false for valid topology', () => {
    const node = createMockNode('node-1', 'test-node');
    expect(hasValidationErrors([node], [], 'my-topology')).toBe(false);
  });
});

describe('getNodeIssues', () => {
  it('returns issues for specific node', () => {
    const node1 = createMockNode('node-1', '');
    const node2 = createMockNode('node-2', 'valid');
    
    const result = validateTopology([node1, node2], [], '', { checkNameFormat: true });
    const node1Issues = getNodeIssues(result, 'node-1');
    
    expect(node1Issues.length).toBeGreaterThan(0);
    expect(node1Issues[0].nodeId).toBe('node-1');
  });

  it('returns empty array for node with no issues', () => {
    const node = createMockNode('node-1', 'valid-name');
    // Create a valid topology with no warnings
    const result = validateTopology([node], [], 'test-topology', {
      checkIsolatedNodes: false,
      checkDuplicateNames: false,
    });
    const issues = getNodeIssues(result, 'node-1');
    
    expect(issues).toHaveLength(0);
  });
});

describe('getEdgeIssues', () => {
  it('returns issues for specific edge', () => {
    const node1 = createMockNode('node-1', 'drone-1');
    const node2 = createMockNode('node-2', 'drone-2');
    const edge = createMockEdge('edge-1', 'node-1', 'node-2', {
      bandwidth: 'invalid',
      latency: '5ms',
      jitter: '1ms',
      packetLoss: '0%',
    });
    
    const result = validateTopology([node1, node2], [edge], '', { checkInvalidPolicies: true });
    const edgeIssues = getEdgeIssues(result, 'edge-1');
    
    expect(edgeIssues.length).toBeGreaterThan(0);
    expect(edgeIssues[0].edgeId).toBe('edge-1');
  });

  it('returns empty array for edge with no issues', () => {
    const node1 = createMockNode('node-1', 'drone-1');
    const node2 = createMockNode('node-2', 'drone-2');
    const edge = createMockEdge('edge-1', 'node-1', 'node-2', {
      bandwidth: '10Mbps',
      latency: '5ms',
      jitter: '1ms',
      packetLoss: '0%',
    });
    
    const result = validateTopology([node1, node2], [edge], '');
    const issues = getEdgeIssues(result, 'edge-1');
    
    expect(issues).toHaveLength(0);
  });
});
