import { useState, useCallback, useEffect, useMemo } from 'react';
import Editor from '@monaco-editor/react';
import yaml from 'js-yaml';
import ReactFlow, {
  type Node,
  Position,
  useNodesState,
  Background,
  BackgroundVariant,
} from 'reactflow';
import 'reactflow/dist/style.css';
import type { NetworkTopology, NodeGroup } from '../types/api';
import { apiClient } from '../api/client';
import './TopologyCreate.css';

// ============================================================================
// Types
// ============================================================================

interface TopologyCreateProps {
  onCreated?: (name: string, namespace: string) => void;
  onCancel?: () => void;
  isEdit?: boolean;
  initialTopology?: NetworkTopology;
}

// ============================================================================
// Constants
// ============================================================================

const DEFAULT_NAMESPACE = 'kuro-experiment';

const GROUP_COLORS = [
  '#3b82f6', // blue
  '#10b981', // green
  '#f59e0b', // amber
  '#8b5cf6', // purple
  '#ec4899', // pink
  '#06b6d4', // cyan
  '#ef4444', // red
  '#84cc16', // lime
];

// Default YAML template
const DEFAULT_YAML = `apiVersion: simulation.kuro.io/v1alpha1
kind: NetworkTopology
metadata:
  name: topology-demo
  namespace: kuro-experiment
spec:
  nodeGroups:
    - name: leader
      replicas: 1
      image: busybox:latest
      command:
        - sleep
        - infinite
      labels:
        role: leader
    - name: follower
      replicas: 3
      image: busybox:latest
      command:
        - sleep
        - infinite
      labels:
        role: follower
`;

// ============================================================================
// YAML Utilities
// ============================================================================

function yamlToTopology(yamlContent: string): { topology: NetworkTopology | null; error: string | null } {
  try {
    const parsed = yaml.load(yamlContent) as unknown;

    if (!parsed || typeof parsed !== 'object') {
      return { topology: null, error: 'Invalid YAML structure' };
    }

    const topology = parsed as NetworkTopology;

    // Basic validation
    if (topology.kind !== 'NetworkTopology') {
      return { topology: null, error: 'Kind must be NetworkTopology' };
    }

    if (!topology.metadata?.name) {
      return { topology: null, error: 'metadata.name is required' };
    }

    if (!topology.spec?.nodeGroups || !Array.isArray(topology.spec.nodeGroups)) {
      return { topology: null, error: 'spec.nodeGroups array is required' };
    }

    if (topology.spec.nodeGroups.length === 0) {
      return { topology: null, error: 'At least one nodeGroup is required' };
    }

    // Validate each nodeGroup
    for (const group of topology.spec.nodeGroups) {
      if (!group.name) {
        return { topology: null, error: 'Each nodeGroup must have a name' };
      }
      if (!group.image) {
        return { topology: null, error: `NodeGroup "${group.name}" must have an image` };
      }
    }

    return { topology, error: null };
  } catch (e) {
    const errorMessage = e instanceof Error ? e.message : 'Unknown parsing error';
    return { topology: null, error: errorMessage };
  }
}

// ============================================================================
// Topology Preview Component
// ============================================================================

interface TopologyPreviewProps {
  nodeGroups: NodeGroup[];
}

function TopologyPreview({ nodeGroups }: TopologyPreviewProps) {
  // Generate nodes from node groups
  const initialNodes = useMemo(() => {
    const nodes: Node[] = [];
    const centerX = 300;
    const centerY = 200;
    const radius = Math.min(150, 50 + nodeGroups.length * 30);

    nodeGroups.forEach((group, groupIndex) => {
      const color = GROUP_COLORS[groupIndex % GROUP_COLORS.length];
      const angle = (2 * Math.PI * groupIndex) / nodeGroups.length - Math.PI / 2;
      const x = centerX + radius * Math.cos(angle);
      const y = centerY + radius * Math.sin(angle);

      nodes.push({
        id: group.name,
        type: 'default',
        position: { x, y },
        data: {
          label: (
            <div style={{ padding: '8px 12px', minWidth: '80px' }}>
              <div style={{ fontWeight: 600, color: '#e2e8f0' }}>{group.name}</div>
              <div style={{ fontSize: '11px', color: '#94a3b8', marginTop: '2px' }}>
                {group.replicas} {group.replicas === 1 ? 'replica' : 'replicas'}
              </div>
            </div>
          ),
        },
        style: {
          background: '#1a1a2e',
          border: `2px solid ${color}`,
          borderRadius: '8px',
          fontSize: '12px',
        },
        sourcePosition: Position.Right,
        targetPosition: Position.Left,
      });
    });

    return nodes;
  }, [nodeGroups]);

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);

  // Update nodes when nodeGroups change
  useEffect(() => {
    setNodes(initialNodes);
  }, [initialNodes, setNodes]);

  return (
    <div className="topology-preview">
      <ReactFlow
        nodes={nodes}
        onNodesChange={onNodesChange}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        minZoom={0.5}
        maxZoom={1.5}
        nodesDraggable={true}
        nodesConnectable={false}
        elementsSelectable={true}
        panOnDrag={true}
        zoomOnScroll={true}
        proOptions={{ hideAttribution: true }}
      >
        <Background variant={BackgroundVariant.Dots} gap={20} size={1} color="#2d2d44" />
      </ReactFlow>
    </div>
  );
}

// ============================================================================
// Main Component
// ============================================================================

export function TopologyCreate({ onCreated, onCancel, isEdit = false, initialTopology }: TopologyCreateProps) {
  // YAML content state
  const [yamlContent, setYamlContent] = useState(() => {
    if (initialTopology) {
      return yaml.dump(initialTopology, { indent: 2, lineWidth: -1, noRefs: true });
    }
    return DEFAULT_YAML;
  });

  // Parsed topology state
  const [topology, setTopology] = useState<NetworkTopology | null>(null);
  const [parseError, setParseError] = useState<string | null>(null);

  // UI state
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  // Parse initial YAML on mount
  useEffect(() => {
    const { topology: parsed, error } = yamlToTopology(yamlContent);
    if (error) {
      setParseError(error);
      setTopology(null);
    } else {
      setParseError(null);
      setTopology(parsed);
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Parse YAML on change
  const handleYamlChange = useCallback((value: string | undefined) => {
    const content = value || '';
    setYamlContent(content);

    const { topology: parsed, error } = yamlToTopology(content);
    if (error) {
      setParseError(error);
      setTopology(null);
    } else {
      setParseError(null);
      setTopology(parsed);
    }
  }, []);

  // Handle submit
  const handleSubmit = useCallback(async () => {
    if (!topology) return;

    setCreating(true);
    setCreateError(null);

    try {
      let response;
      if (isEdit) {
        response = await apiClient.updateTopology(topology);
      } else {
        response = await apiClient.createTopology(topology);
      }

      if (response.success) {
        console.log(isEdit ? 'Topology updated successfully:' : 'Topology created successfully:', response.data);
        onCreated?.(topology.metadata.name, topology.metadata.namespace || DEFAULT_NAMESPACE);
      } else {
        setCreateError(response.error || `Failed to ${isEdit ? 'update' : 'create'} topology`);
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setCreateError(errorMessage);
      console.error(`Failed to ${isEdit ? 'update' : 'create'} topology:`, err);
    } finally {
      setCreating(false);
    }
  }, [topology, isEdit, onCreated]);

  // Handle import from session storage
  useEffect(() => {
    const importedTopologyJson = sessionStorage.getItem('importedTopology');
    if (importedTopologyJson) {
      try {
        const importedTopology = JSON.parse(importedTopologyJson) as NetworkTopology;
        const yamlStr = yaml.dump(importedTopology, { indent: 2, lineWidth: -1, noRefs: true });
        setYamlContent(yamlStr);
        setTopology(importedTopology);
        sessionStorage.removeItem('importedTopology');
      } catch {
        console.error('Failed to parse imported topology');
      }
    }
  }, []);

  // Calculate stats
  const nodeGroups = topology?.spec?.nodeGroups || [];
  const totalNodes = nodeGroups.reduce((sum, g) => sum + g.replicas, 0);
  const isValid = topology !== null && !parseError;

  return (
    <div className="topology-create yaml-first-layout">
      {/* Header */}
      <div className="create-header">
        <div className="create-header-left">
          {onCancel && (
            <button className="btn-back" onClick={onCancel} disabled={creating}>
              ← Back
            </button>
          )}
          <h2>{isEdit ? 'Edit Topology' : 'Create Topology'}</h2>
        </div>
        <div className="create-header-right">
          <div className="header-stats">
            <span className="stat-badge">{nodeGroups.length} groups</span>
            <span className="stat-badge">{totalNodes} nodes</span>
          </div>
          <button
            className="btn-primary"
            onClick={handleSubmit}
            disabled={!isValid || creating}
          >
            {creating ? (isEdit ? 'Updating...' : 'Creating...') : (isEdit ? 'Update Topology' : 'Create Topology')}
          </button>
        </div>
      </div>

      {/* Error Banner */}
      {(parseError || createError) && (
        <div className="error-banner">
          <span className="error-icon">⚠</span>
          <span className="error-message">{parseError || createError}</span>
        </div>
      )}

      {/* Main Content - Split Layout */}
      <div className="create-content-split">
        {/* Left: YAML Editor */}
        <div className="yaml-editor-panel">
          <div className="panel-header">
            <h3>YAML Definition</h3>
            <span className="hint">Define your topology in YAML format</span>
          </div>
          <div className="yaml-editor-wrapper">
            <Editor
              height="100%"
              defaultLanguage="yaml"
              value={yamlContent}
              onChange={handleYamlChange}
              theme="vs-dark"
              options={{
                minimap: { enabled: false },
                fontSize: 13,
                lineNumbers: 'on',
                wordWrap: 'on',
                automaticLayout: true,
                scrollBeyondLastLine: false,
                tabSize: 2,
                folding: true,
                renderWhitespace: 'selection',
              }}
            />
          </div>
        </div>

        {/* Right: Topology Preview */}
        <div className="topology-preview-panel">
          <div className="panel-header">
            <h3>Live Preview</h3>
            <span className="hint">
              {isValid ? 'Topology visualization' : 'Fix YAML errors to see preview'}
            </span>
          </div>
          <div className="topology-preview-wrapper">
            {isValid ? (
              <TopologyPreview nodeGroups={nodeGroups} />
            ) : (
              <div className="preview-placeholder">
                <div className="placeholder-icon">📊</div>
                <div className="placeholder-text">
                  {parseError ? 'Fix YAML errors to see preview' : 'Enter YAML to see preview'}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default TopologyCreate;
