import { useState, useCallback, useRef, useEffect, useMemo, memo } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  addEdge,
  type Node,
  type Edge,
  type Connection,
  type OnConnect,
  MarkerType,
  Panel,
  SelectionMode,
} from 'reactflow';
import 'reactflow/dist/style.css';

import NodePalette from '../components/topology/NodePalette';
import NodeCard from '../components/topology/NodeCard';
import NodeConfigPanel, { type NodeConfig } from '../components/topology/NodeConfigPanel';
import LinkConfigPanel from '../components/topology/LinkConfigPanel';
import NodeGroupPanel, { type NodeGroupInfo, type GroupConfig } from '../components/topology/NodeGroupPanel';
import YamlPreviewDialog from '../components/topology/YamlPreviewDialog';
import type { NodeRole, TopologyNode, TrafficPolicy } from '../types/api';
import { editorStateToYaml } from '../utils/topologyConverter';
import './TopologyEditor.css';

// ============================================================================
// Types
// ============================================================================

interface EditorNodeData {
  node: TopologyNode;
  isSelected: boolean;
}

interface EditorEdgeData {
  policy?: TrafficPolicy;
}

export interface TopologyEditorProps {
  onSave?: (yaml: string) => void;
  onCancel?: () => void;
  initialNodes?: Node<EditorNodeData>[];
  initialEdges?: Edge<EditorEdgeData>[];
  initialName?: string;
}

type ConfigPanelTab = 'node' | 'group';

// ============================================================================
// Constants
// ============================================================================

const NODE_TYPES = {
  custom: NodeCard,
};

const DEFAULT_NODE_CONFIGS: Record<NodeRole, { image: string; color: string }> = {
  drone: { image: 'nicolaka/netshoot', color: '#3b82f6' },
  'ground-station': { image: 'nicolaka/netshoot', color: '#10b981' },
  gateway: { image: 'nicolaka/netshoot', color: '#f59e0b' },
  server: { image: 'nginx:alpine', color: '#8b5cf6' },
  client: { image: 'busybox', color: '#ec4899' },
  custom: { image: 'busybox', color: '#6b7280' },
};

// Default link policy for new connections
const DEFAULT_LINK_POLICY: TrafficPolicy = {
  bandwidth: '10Mbps',
  latency: '5ms',
  jitter: '1ms',
  packetLoss: '0.1%',
};

// ============================================================================
// Component
// ============================================================================

function TopologyEditor({
  onSave,
  onCancel,
  initialNodes = [],
  initialEdges = [],
  initialName = 'my-topology',
}: TopologyEditorProps) {
  const reactFlowWrapper = useRef<HTMLDivElement>(null);
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);
  const [selectedNodeIds, setSelectedNodeIds] = useState<Set<string>>(new Set());
  const [paletteCollapsed, setPaletteCollapsed] = useState(false);
  const [nodeCounter, setNodeCounter] = useState(1);
  
  // Config panel tab
  const [configPanelTab, setConfigPanelTab] = useState<ConfigPanelTab>('node');
  
  // Node groups state
  const [nodeGroups, setNodeGroups] = useState<NodeGroupInfo[]>([]);
  
  // YAML Preview state
  const [topologyName, setTopologyName] = useState(initialName);
  const [isPreviewOpen, setIsPreviewOpen] = useState(false);
  const [previewYaml, setPreviewYaml] = useState('');
  const [previewErrors, setPreviewErrors] = useState<string[]>([]);
  const [previewWarnings, setPreviewWarnings] = useState<string[]>([]);

  // Handle keyboard events for delete
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Delete' || event.key === 'Backspace') {
        // Prevent default to avoid browser back navigation on Backspace
        event.preventDefault();
        
        if (selectedEdgeId) {
          // Delete selected edge
          setEdges((eds) => eds.filter((e) => e.id !== selectedEdgeId));
          setSelectedEdgeId(null);
        } else if (selectedNodeIds.size > 0) {
          // Delete all selected nodes and their connected edges
          const idsToDelete = Array.from(selectedNodeIds);
          setNodes((nds) => nds.filter((n) => !idsToDelete.includes(n.id)));
          setEdges((eds) =>
            eds.filter((e) => !idsToDelete.includes(e.source) && !idsToDelete.includes(e.target))
          );
          setSelectedNodeIds(new Set());
          setSelectedNodeId(null);
        } else if (selectedNodeId) {
          // Delete single selected node
          setNodes((nds) => nds.filter((n) => n.id !== selectedNodeId));
          setEdges((eds) =>
            eds.filter((e) => e.source !== selectedNodeId && e.target !== selectedNodeId)
          );
          setSelectedNodeId(null);
        }
      }
      
      // Escape to clear multi-selection
      if (event.key === 'Escape') {
        setSelectedNodeIds(new Set());
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [selectedNodeId, selectedEdgeId, selectedNodeIds, setNodes, setEdges]);

  // Handle drop from palette
  const onDragOver = useCallback((event: React.DragEvent) => {
    event.preventDefault();
    event.dataTransfer.dropEffect = 'move';
  }, []);

  const onDrop = useCallback(
    (event: React.DragEvent) => {
      event.preventDefault();

      const dataStr = event.dataTransfer.getData('application/reactflow');
      if (!dataStr) return;

      const data = JSON.parse(dataStr);
      const type = data.type as NodeRole;

      // Get drop position relative to React Flow
      const reactFlowBounds = reactFlowWrapper.current?.getBoundingClientRect();
      if (!reactFlowBounds) return;

      const position = {
        x: event.clientX - reactFlowBounds.left,
        y: event.clientY - reactFlowBounds.top,
      };

      // Create new node
      const nodeId = `node-${nodeCounter}`;
      const newNode: Node<EditorNodeData> = {
        id: nodeId,
        type: 'custom',
        position,
        data: {
          node: {
            id: nodeId,
            name: `${type}-${nodeCounter}`,
            role: type,
            ip: `10.0.0.${nodeCounter}`,
            labels: { role: type },
            status: 'pending',
            groupId: '',
          },
          isSelected: false,
        },
      };

      setNodes((nds) => [...nds, newNode]);
      setNodeCounter((c) => c + 1);
    },
    [nodeCounter, setNodes]
  );

  // Handle node click - supports multi-select with shift key
  const handleNodeClick = useCallback(
    (event: React.MouseEvent, node: Node<EditorNodeData>) => {
      const isShiftClick = event.shiftKey;
      
      if (isShiftClick) {
        // Multi-select mode: toggle selection
        setSelectedNodeIds((prev) => {
          const next = new Set(prev);
          if (next.has(node.id)) {
            next.delete(node.id);
          } else {
            next.add(node.id);
          }
          return next;
        });
        setSelectedNodeId(null);
        setSelectedEdgeId(null);
        
        // Update node visual selection state
        setNodes((nds) =>
          nds.map((n) => {
            const willBeSelected = n.id === node.id 
              ? !selectedNodeIds.has(node.id) 
              : selectedNodeIds.has(n.id);
            return {
              ...n,
              data: {
                ...n.data,
                isSelected: willBeSelected,
              },
            };
          })
        );
      } else {
        // Single-select mode
        setSelectedNodeId(node.id);
        setSelectedNodeIds(new Set([node.id]));
        setSelectedEdgeId(null);
        
        // Update node selection state
        setNodes((nds) =>
          nds.map((n) => ({
            ...n,
            data: {
              ...n.data,
              isSelected: n.id === node.id,
            },
          }))
        );
      }
      
      // Switch to node config panel
      setConfigPanelTab('node');
    },
    [setNodes, selectedNodeIds]
  );

  // Handle node config change
  const handleNodeConfigChange = useCallback(
    (nodeId: string, config: Partial<NodeConfig>) => {
      setNodes((nds) =>
        nds.map((n) => {
          if (n.id !== nodeId) return n;
          return {
            ...n,
            data: {
              ...n.data,
              node: {
                ...n.data.node,
                name: config.name ?? n.data.node.name,
                labels: config.labels ?? n.data.node.labels,
              },
            },
          };
        })
      );
    },
    [setNodes]
  );

  // Handle node delete from config panel
  const handleNodeDelete = useCallback(
    (nodeId: string) => {
      setNodes((nds) => nds.filter((n) => n.id !== nodeId));
      setEdges((eds) =>
        eds.filter((e) => e.source !== nodeId && e.target !== nodeId)
      );
      setSelectedNodeId(null);
    },
    [setNodes, setEdges]
  );

  // Handle edge policy change
  const handleEdgePolicyChange = useCallback(
    (edgeId: string, policy: TrafficPolicy) => {
      setEdges((eds) =>
        eds.map((e) => {
          if (e.id !== edgeId) return e;
          return {
            ...e,
            label: policy.bandwidth,
            data: {
              ...e.data,
              policy,
            },
          };
        })
      );
    },
    [setEdges]
  );

  // Handle edge delete from config panel
  const handleEdgeDelete = useCallback(
    (edgeId: string) => {
      setEdges((eds) => eds.filter((e) => e.id !== edgeId));
      setSelectedEdgeId(null);
    },
    [setEdges]
  );

  // Get selected node for config panel
  const selectedNode = selectedNodeId
    ? nodes.find((n) => n.id === selectedNodeId)?.data.node ?? null
    : null;

  // Get selected edge for config panel
  const selectedEdge = selectedEdgeId
    ? edges.find((e) => e.id === selectedEdgeId) ?? null
    : null;

  // Handle connection (link drawing)
  const onConnect: OnConnect = useCallback(
    (connection: Connection) => {
      if (!connection.source || !connection.target) return;

      // Check if edge already exists
      const edgeExists = edges.some(
        (e) =>
          (e.source === connection.source && e.target === connection.target) ||
          (e.source === connection.target && e.target === connection.source)
      );
      if (edgeExists) return;

      const edgeId = `edge-${connection.source}-${connection.target}`;
      const newEdge: Edge<EditorEdgeData> = {
        id: edgeId,
        source: connection.source,
        target: connection.target,
        type: 'smoothstep',
        animated: true,
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: '#94a3b8',
        },
        style: {
          stroke: '#94a3b8',
          strokeWidth: 1.5,
        },
        label: DEFAULT_LINK_POLICY.bandwidth,
        labelStyle: { fill: '#64748b', fontWeight: 500, fontSize: 10 },
        labelBgStyle: { fill: '#1e1e2e', fillOpacity: 0.9 },
        labelBgPadding: [4, 2] as [number, number],
        labelBgBorderRadius: 4,
        data: {
          policy: DEFAULT_LINK_POLICY,
        },
      };
      setEdges((eds) => addEdge(newEdge, eds));
      
      // Select the newly created edge
      setSelectedEdgeId(edgeId);
      setSelectedNodeId(null);
    },
    [edges, setEdges]
  );

  // Handle edge click (link selection)
  const handleEdgeClick = useCallback(
    (_event: React.MouseEvent, edge: Edge<EditorEdgeData>) => {
      // Deselect node and select edge
      setSelectedNodeId(null);
      setSelectedEdgeId(edge.id);

      // Update edge visual state
      setEdges((eds) =>
        eds.map((e) => ({
          ...e,
          style: {
            ...(e.style || {}),
            stroke: e.id === edge.id ? '#3b82f6' : '#94a3b8',
            strokeWidth: e.id === edge.id ? 2 : 1.5,
          },
          markerEnd: {
            ...(typeof e.markerEnd === 'object' ? e.markerEnd : {}),
            type: MarkerType.ArrowClosed,
            color: e.id === edge.id ? '#3b82f6' : '#94a3b8',
          },
        }))
      );
    },
    [setEdges]
  );

  // Handle pane click (deselect all)
  const handlePaneClick = useCallback(() => {
    setSelectedNodeId(null);
    setSelectedEdgeId(null);
    setSelectedNodeIds(new Set());

    // Reset node selection state
    setNodes((nds) =>
      nds.map((n) => ({
        ...n,
        data: {
          ...n.data,
          isSelected: false,
        },
      }))
    );

    // Reset edge styles
    setEdges((eds) =>
      eds.map((e) => ({
        ...e,
        style: {
          ...(e.style || {}),
          stroke: '#94a3b8',
          strokeWidth: 1.5,
        },
        markerEnd: {
          ...(typeof e.markerEnd === 'object' ? e.markerEnd : {}),
          type: MarkerType.ArrowClosed,
          color: '#94a3b8',
        },
      }))
    );
  }, [setNodes, setEdges]);

  // Handle delete selected (node, edge, or multiple nodes)
  const handleDelete = useCallback(() => {
    if (selectedEdgeId) {
      // Delete selected edge
      setEdges((eds) => eds.filter((e) => e.id !== selectedEdgeId));
      setSelectedEdgeId(null);
    } else if (selectedNodeIds.size > 0) {
      // Delete all selected nodes and their connected edges
      const idsToDelete = Array.from(selectedNodeIds);
      setNodes((nds) => nds.filter((n) => !idsToDelete.includes(n.id)));
      setEdges((eds) =>
        eds.filter((e) => !idsToDelete.includes(e.source) && !idsToDelete.includes(e.target))
      );
      setSelectedNodeIds(new Set());
      setSelectedNodeId(null);
    } else if (selectedNodeId) {
      // Delete single selected node
      setNodes((nds) => nds.filter((n) => n.id !== selectedNodeId));
      setEdges((eds) =>
        eds.filter((e) => e.source !== selectedNodeId && e.target !== selectedNodeId)
      );
      setSelectedNodeId(null);
    }
  }, [selectedNodeId, selectedEdgeId, selectedNodeIds, setNodes, setEdges]);

  // Handle save button click - show YAML preview
  const handleSaveClick = useCallback(() => {
    const result = editorStateToYaml(
      nodes as Node<EditorNodeData>[],
      edges as Edge<EditorEdgeData>[],
      {
        topologyName,
        namespace: 'default',
      }
    );
    
    setPreviewYaml(result.yaml);
    setPreviewErrors(result.errors);
    setPreviewWarnings(result.warnings);
    setIsPreviewOpen(true);
  }, [nodes, edges, topologyName]);

  // Handle actual save from dialog
  const handleSaveFromDialog = useCallback(() => {
    if (previewErrors.length === 0 && onSave) {
      onSave(previewYaml);
    }
  }, [previewErrors, previewYaml, onSave]);

  // Close preview dialog
  const handleClosePreview = useCallback(() => {
    setIsPreviewOpen(false);
  }, []);

  // ========================================================================
  // Node Group Management
  // ========================================================================

  // Available nodes for group panel
  const availableNodes = useMemo(
    () => nodes.map((n) => ({
      id: n.id,
      name: n.data.node.name,
      role: n.data.node.role,
    })),
    [nodes]
  );

  // Create a new node group
  const handleCreateGroup = useCallback(
    (_name: string, nodeIds: string[], config: GroupConfig) => {
      const newGroup: NodeGroupInfo = {
        id: `group-${Date.now()}`,
        name: config.name,
        role: nodeIds.length > 0 
          ? nodes.find((n) => n.id === nodeIds[0])?.data.node.role || 'custom'
          : 'custom',
        replicas: config.replicas,
        image: config.image,
        labels: config.labels,
        nodeIds,
      };
      
      setNodeGroups((prev) => [...prev, newGroup]);
      
      // Update nodes with group assignment
      setNodes((nds) =>
        nds.map((n) => {
          if (!nodeIds.includes(n.id)) return n;
          return {
            ...n,
            data: {
              ...n.data,
              node: {
                ...n.data.node,
                groupId: newGroup.id,
              },
            },
          };
        })
      );
      
      // Clear selection
      setSelectedNodeIds(new Set());
    },
    [nodes, setNodes]
  );

  // Update an existing group
  const handleUpdateGroup = useCallback(
    (groupId: string, config: GroupConfig) => {
      setNodeGroups((prev) =>
        prev.map((g) =>
          g.id === groupId
            ? { ...g, name: config.name, replicas: config.replicas, image: config.image, labels: config.labels }
            : g
        )
      );
    },
    []
  );

  // Delete a group
  const handleDeleteGroup = useCallback(
    (groupId: string) => {
      setNodeGroups((prev) => prev.filter((g) => g.id !== groupId));
      
      // Clear group assignment from nodes
      setNodes((nds) =>
        nds.map((n) => {
          if (n.data.node.groupId !== groupId) return n;
          return {
            ...n,
            data: {
              ...n.data,
              node: {
                ...n.data.node,
                groupId: '',
              },
            },
          };
        })
      );
    },
    [setNodes]
  );

  // Add nodes to existing group
  const handleAddNodesToGroup = useCallback(
    (groupId: string, nodeIds: string[]) => {
      setNodeGroups((prev) =>
        prev.map((g) => {
          if (g.id !== groupId) return g;
          const newNodeIds = [...new Set([...g.nodeIds, ...nodeIds])];
          return { ...g, nodeIds: newNodeIds, replicas: newNodeIds.length };
        })
      );
      
      // Update nodes with group assignment
      setNodes((nds) =>
        nds.map((n) => {
          if (!nodeIds.includes(n.id)) return n;
          return {
            ...n,
            data: {
              ...n.data,
              node: {
                ...n.data.node,
                groupId,
              },
            },
          };
        })
      );
    },
    [setNodes]
  );

  // Remove a node from group
  const handleRemoveNodeFromGroup = useCallback(
    (groupId: string, nodeId: string) => {
      setNodeGroups((prev) =>
        prev.map((g) => {
          if (g.id !== groupId) return g;
          const newNodeIds = g.nodeIds.filter((id) => id !== nodeId);
          return { ...g, nodeIds: newNodeIds, replicas: newNodeIds.length };
        })
      );
      
      // Clear group assignment from node
      setNodes((nds) =>
        nds.map((n) => {
          if (n.id !== nodeId) return n;
          return {
            ...n,
            data: {
              ...n.data,
              node: {
                ...n.data.node,
                groupId: '',
              },
            },
          };
        })
      );
    },
    [setNodes]
  );

  return (
    <div className="topology-editor">
      <div className="editor-sidebar">
        <NodePalette
          collapsed={paletteCollapsed}
          onNodeDragStart={() => setPaletteCollapsed(true)}
        />
      </div>

      <div className="editor-main" ref={reactFlowWrapper}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          onNodeClick={handleNodeClick}
          onEdgeClick={handleEdgeClick}
          onPaneClick={handlePaneClick}
          onDragOver={onDragOver}
          onDrop={onDrop}
          nodeTypes={NODE_TYPES}
          fitView
          minZoom={0.2}
          maxZoom={2}
          deleteKeyCode={null}
          selectionOnDrag
          selectionMode={SelectionMode.Partial}
          multiSelectionKeyCode="Shift"
        >
          <Background gap={16} size={1} />
          <Controls showInteractive={false} />
          <MiniMap
            nodeColor={(node) => {
              const data = node.data as EditorNodeData | undefined;
              const role = data?.node?.role;
              if (role) {
                return DEFAULT_NODE_CONFIGS[role]?.color || '#6b7280';
              }
              return '#6b7280';
            }}
            maskColor="rgba(0, 0, 0, 0.05)"
          />
          <Panel position="top-right" className="editor-toolbar">
            <div className="topology-name-input">
              <input
                type="text"
                value={topologyName}
                onChange={(e) => setTopologyName(e.target.value)}
                placeholder="Topology name"
                className="topology-name-field"
              />
            </div>
            <div className="selection-info">
              {selectedNodeIds.size > 1 && (
                <span className="selection-count">{selectedNodeIds.size} nodes selected</span>
              )}
            </div>
            <button className="btn-secondary" onClick={onCancel}>
              Cancel
            </button>
            <button
              className="btn-danger"
              onClick={handleDelete}
              disabled={!selectedNodeId && !selectedEdgeId && selectedNodeIds.size === 0}
            >
              Delete
            </button>
            <button className="btn-primary" onClick={handleSaveClick}>
              Save Topology
            </button>
          </Panel>
        </ReactFlow>
      </div>

      <div className="editor-config">
        {selectedEdgeId ? (
          <LinkConfigPanel
            linkId={selectedEdgeId}
            sourceName={selectedEdge?.source ? nodes.find(n => n.id === selectedEdge.source)?.data?.node?.name || selectedEdge.source : ''}
            targetName={selectedEdge?.target ? nodes.find(n => n.id === selectedEdge.target)?.data?.node?.name || selectedEdge.target : ''}
            policy={selectedEdge?.data?.policy || null}
            onPolicyChange={handleEdgePolicyChange}
            onDelete={handleEdgeDelete}
            onClose={() => setSelectedEdgeId(null)}
          />
        ) : (
          <>
            <div className="config-panel-tabs">
              <button
                className={`config-panel-tab ${configPanelTab === 'node' ? 'active' : ''}`}
                onClick={() => setConfigPanelTab('node')}
              >
                Node
              </button>
              <button
                className={`config-panel-tab ${configPanelTab === 'group' ? 'active' : ''}`}
                onClick={() => setConfigPanelTab('group')}
              >
                Groups
              </button>
            </div>
            {configPanelTab === 'group' ? (
              <NodeGroupPanel
                groups={nodeGroups}
                selectedNodeIds={Array.from(selectedNodeIds)}
                availableNodes={availableNodes}
                onCreateGroup={handleCreateGroup}
                onUpdateGroup={handleUpdateGroup}
                onDeleteGroup={handleDeleteGroup}
                onAddNodesToGroup={handleAddNodesToGroup}
                onRemoveNodeFromGroup={handleRemoveNodeFromGroup}
              />
            ) : (
              <NodeConfigPanel
                node={selectedNode}
                onConfigChange={handleNodeConfigChange}
                onDelete={handleNodeDelete}
                onClose={() => setSelectedNodeId(null)}
              />
            )}
          </>
        )}
      </div>

      <YamlPreviewDialog
        isOpen={isPreviewOpen}
        yaml={previewYaml}
        topologyName={topologyName}
        errors={previewErrors}
        warnings={previewWarnings}
        onClose={handleClosePreview}
        onSave={handleSaveFromDialog}
      />
    </div>
  );
}

export default memo(TopologyEditor);