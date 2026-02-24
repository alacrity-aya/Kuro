import { useState, useCallback, useEffect } from 'react';
import Editor from '@monaco-editor/react';
import yaml from 'js-yaml';
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
} from 'reactflow';
import type { Node, Edge } from 'reactflow';
import dagre from 'dagre';
import 'reactflow/dist/style.css';
import type { NetworkTopology, NodeGroup } from '../types/api';
import { apiClient } from '../api/client';
import './TopologyCreate.css';

// Default YAML template
const DEFAULT_YAML = `apiVersion: simulation.kuro.io/v1alpha1
kind: NetworkTopology
metadata:
  name: my-topology
  namespace: kuro-experiment
spec:
  nodeGroups:
    - name: leader
      replicas: 1
      image: busybox:latest
      command:
        - sleep
        - "3600"
      labels:
        role: leader
    - name: follower
      replicas: 2
      image: busybox:latest
      command:
        - sleep
        - "3600"
      labels:
        role: follower
`;

// Dagre layout configuration
const dagreConfig = {
  nodesep: 80,
  ranksep: 120,
  rankdir: 'TB' as const,
};

// Apply dagre layout to nodes and edges
function applyLayout(nodes: Node[], edges: Edge[]): { nodes: Node[]; edges: Edge[] } {
  const dagreGraph = new dagre.graphlib.Graph();
  dagreGraph.setDefaultEdgeLabel(() => ({}));
  dagreGraph.setGraph(dagreConfig);

  nodes.forEach((node) => {
    dagreGraph.setNode(node.id, { width: 180, height: 80 });
  });

  edges.forEach((edge) => {
    dagreGraph.setEdge(edge.source, edge.target);
  });

  dagre.layout(dagreGraph);

  const layoutedNodes = nodes.map((node) => {
    const nodeWithPosition = dagreGraph.node(node.id);
    return {
      ...node,
      position: {
        x: nodeWithPosition.x - 90,
        y: nodeWithPosition.y - 40,
      },
    };
  });

  return { nodes: layoutedNodes, edges };
}

// Generate preview nodes from parsed topology
function generatePreviewNodes(topology: NetworkTopology): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = [];
  const edges: Edge[] = [];
  const nodeGroups = topology.spec?.nodeGroups || [];

  let nodeIndex = 0;

  nodeGroups.forEach((group: NodeGroup, groupIndex: number) => {
    const replicas = group.replicas || 1;
    const role = group.labels?.role || group.name;

    for (let i = 0; i < replicas; i++) {
      const nodeId = `node-${nodeIndex}`;
      const nodeName = replicas > 1 ? `${group.name}-${i}` : group.name;

      nodes.push({
        id: nodeId,
        type: 'default',
        data: {
          label: (
            <div className="preview-node">
              <div className="preview-node-name">{nodeName}</div>
              <div className="preview-node-role">{role}</div>
            </div>
          ),
        },
        position: { x: 0, y: 0 },
        className: `preview-node-wrapper group-${groupIndex % 4}`,
      });

      nodeIndex++;
    }
  });

  // Create edges between groups (leader-follower pattern)
  if (nodeGroups.length >= 2) {
    const leaderNodes = nodes.filter((n) => 
      n.data.label.props.className?.includes('group-0')
    );
    const followerNodes = nodes.filter((n) => 
      !n.data.label.props.className?.includes('group-0')
    );

    leaderNodes.forEach((leader, i) => {
      followerNodes.forEach((follower, j) => {
        edges.push({
          id: `edge-${i}-${j}`,
          source: leader.id,
          target: follower.id,
          animated: true,
          style: { stroke: '#4a90d9', strokeWidth: 2 },
        });
      });
    });
  }

  return applyLayout(nodes, edges);
}

// Parse YAML and return topology or error
function parseYAML(yamlContent: string): { topology: NetworkTopology | null; error: string | null } {
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

interface TopologyCreateProps {
  onCreated?: (name: string, namespace: string) => void;
  onCancel?: () => void;
  isEdit?: boolean;
  initialTopology?: NetworkTopology;
}

export function TopologyCreate({ onCreated, onCancel, isEdit = false, initialTopology }: TopologyCreateProps) {
  const [yamlContent, setYamlContent] = useState(() => {
    if (initialTopology) {
      return yaml.dump(initialTopology, {
        indent: 2,
        lineWidth: -1,
        noRefs: true,
      });
    }
    return DEFAULT_YAML;
  });
  const [topology, setTopology] = useState<NetworkTopology | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  // Parse YAML and update preview
  const updatePreview = useCallback((content: string) => {
    const { topology: parsedTopology, error: parseError } = parseYAML(content);

    if (parseError) {
      setError(parseError);
      setTopology(null);
      setNodes([]);
      setEdges([]);
    } else if (parsedTopology) {
      setError(null);
      setTopology(parsedTopology);
      const { nodes: previewNodes, edges: previewEdges } = generatePreviewNodes(parsedTopology);
      setNodes(previewNodes);
      setEdges(previewEdges);
    }
  }, [setNodes, setEdges]);

  // Initial parse
  useEffect(() => {
    // Check for imported topology
    const importedTopologyJson = sessionStorage.getItem('importedTopology');
    if (importedTopologyJson) {
      try {
        const importedTopology = JSON.parse(importedTopologyJson) as NetworkTopology;
        const importedYamlContent = yaml.dump(importedTopology, {
          indent: 2,
          lineWidth: -1,
          noRefs: true,
        });
        // Clear the imported data first
        sessionStorage.removeItem('importedTopology');
        // Update state - the useEffect will re-run with the new yamlContent
        setYamlContent(importedYamlContent);
        return; // Let the next effect run handle the preview update
      } catch {
        console.error('Failed to parse imported topology');
      }
    }
    updatePreview(yamlContent);
  }, [yamlContent, updatePreview]);

  // Handle editor change
  const handleEditorChange = (value: string | undefined) => {
    const content = value || '';
    setYamlContent(content);
    updatePreview(content);
  };

  // Handle create button
  const handleCreate = async () => {
    if (topology && !error) {
      const name = topology.metadata.name;
      const namespace = topology.metadata.namespace || 'kuro-experiment';
      
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
          onCreated?.(name, namespace);
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
    }
  };

  // Count nodes in preview
  const nodeCount = nodes.length;
  const groupCount = topology?.spec?.nodeGroups?.length || 0;

  return (
    <div className="topology-create">
      <div className="create-header">
        <h2>{isEdit ? 'Edit Topology' : 'Create Topology'}</h2>
        <div className="create-actions">
          <button className="btn-secondary" onClick={onCancel} disabled={creating}>
            Cancel
          </button>
          <button 
            className="btn-primary" 
            onClick={handleCreate}
            disabled={!!error || !topology || creating}
          >
            {creating ? (isEdit ? 'Updating...' : 'Creating...') : (isEdit ? 'Update Topology' : 'Create Topology')}
          </button>
        </div>
      </div>

      {error && (
        <div className="error-banner">
          <span className="error-icon">⚠</span>
          <span className="error-message">{error}</span>
        </div>
      )}

      {createError && (
        <div className="error-banner">
          <span className="error-icon">❌</span>
          <span className="error-message">{createError}</span>
        </div>
      )}

      <div className="create-content">
        <div className="editor-panel">
          <div className="panel-header">
            <h3>YAML Editor</h3>
            <span className="hint">Edit the topology definition</span>
          </div>
          <div className="editor-container">
            <Editor
              height="100%"
              defaultLanguage="yaml"
              value={yamlContent}
              onChange={handleEditorChange}
              theme="vs-dark"
              options={{
                minimap: { enabled: false },
                fontSize: 14,
                lineNumbers: 'on',
                wordWrap: 'on',
                automaticLayout: true,
                scrollBeyondLastLine: false,
              }}
            />
          </div>
        </div>

        <div className="preview-panel">
          <div className="panel-header">
            <h3>Live Preview</h3>
            <div className="preview-stats">
              <span className="stat">{groupCount} groups</span>
              <span className="stat">{nodeCount} nodes</span>
            </div>
          </div>
          <div className="preview-container">
            {topology ? (
              <ReactFlow
                nodes={nodes}
                edges={edges}
                onNodesChange={onNodesChange}
                onEdgesChange={onEdgesChange}
                fitView
                fitViewOptions={{ padding: 0.2 }}
                minZoom={0.2}
                maxZoom={1.5}
              >
                <Background color="#333" gap={20} />
                <Controls />
                <MiniMap 
                  nodeColor={(node) => {
                    const className = node.className || '';
                    if (className.includes('group-0')) return '#4a90d9';
                    if (className.includes('group-1')) return '#50c878';
                    if (className.includes('group-2')) return '#f5a623';
                    return '#e74c3c';
                  }}
                  maskColor="rgba(0, 0, 0, 0.7)"
                />
              </ReactFlow>
            ) : (
              <div className="preview-empty">
                <span className="empty-icon">📊</span>
                <p>Fix YAML errors to see preview</p>
              </div>
            )}
          </div>

          {topology && (
            <div className="preview-info">
              <h4>Topology Summary</h4>
              <div className="info-grid">
                <div className="info-item">
                  <span className="info-label">Name</span>
                  <span className="info-value">{topology.metadata.name}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">Namespace</span>
                  <span className="info-value">{topology.metadata.namespace || 'default'}</span>
                </div>
              </div>
              <h4>Node Groups</h4>
              <div className="groups-list">
                {topology.spec.nodeGroups.map((group, index) => (
                  <div key={group.name} className={`group-item group-color-${index % 4}`}>
                    <span className="group-name">{group.name}</span>
                    <span className="group-replicas">×{group.replicas}</span>
                    <span className="group-image">{group.image}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default TopologyCreate;
