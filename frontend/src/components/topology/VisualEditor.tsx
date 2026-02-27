import { memo, useCallback, useMemo, useEffect } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  useNodesState,
  type Node,
  type OnNodesChange,
} from 'reactflow';
import dagre from 'dagre';
import 'reactflow/dist/style.css';

import type { NodeGroup } from '../../types/api';
import './VisualEditor.css';

// ============================================================================
// Types
// ============================================================================

export interface VisualEditorProps {
  /** List of node groups to display */
  nodeGroups: NodeGroup[];
  /** Currently selected group ID (group name) */
  selectedGroupId: string | null;
  /** Handler for group selection */
  onSelectGroup: (groupId: string) => void;
  /** Handler to add a new group */
  onAddGroup: () => void;
}

interface GroupNodeData {
  group: NodeGroup;
  isSelected: boolean;
  color: string;
}

// ============================================================================
// Constants
// ============================================================================

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

const DAGRE_CONFIG = {
  rankdir: 'TB' as const,
  nodesep: 100,
  ranksep: 150,
  align: 'UL' as const,
};

const DEFAULT_VIEWPORT = { x: 0, y: 0, zoom: 0.8 };

// ============================================================================
// Layout Algorithm
// ============================================================================

function getLayoutedNodes(nodes: Node[]): Node[] {
  if (nodes.length === 0) return nodes;

  const dagreGraph = new dagre.graphlib.Graph();
  dagreGraph.setDefaultEdgeLabel(() => ({}));

  dagreGraph.setGraph(DAGRE_CONFIG);

  nodes.forEach((node) => {
    dagreGraph.setNode(node.id, { width: 180, height: 90 });
  });

  dagre.layout(dagreGraph);

  return nodes.map((node) => {
    const nodeWithPosition = dagreGraph.node(node.id);
    return {
      ...node,
      position: {
        x: nodeWithPosition.x - 90,
        y: nodeWithPosition.y - 45,
      },
    };
  });
}

// ============================================================================
// Data Transformation
// ============================================================================

function transformGroupsToNodes(
  groups: NodeGroup[],
  selectedGroupId: string | null
): Node<GroupNodeData>[] {
  return groups.map((group, index) => ({
    id: group.name,
    type: 'default',
    position: { x: 0, y: 0 },
    data: {
      group,
      isSelected: group.name === selectedGroupId,
      color: GROUP_COLORS[index % GROUP_COLORS.length],
    } satisfies GroupNodeData,
    style: {
      background: group.name === selectedGroupId ? '#1e3a5f' : '#1f2937',
      border: `2px solid ${group.name === selectedGroupId ? '#3b82f6' : GROUP_COLORS[index % GROUP_COLORS.length]}`,
      borderRadius: '8px',
      padding: '8px 12px',
      width: 180,
      fontSize: 13,
    },
  }));
}

// ============================================================================
// Custom Node Label Component
// ============================================================================

interface NodeLabelProps {
  group: NodeGroup;
  isSelected: boolean;
  color: string;
}

function NodeLabel({ group, isSelected, color }: NodeLabelProps) {
  return (
    <div className={`visual-editor-node ${isSelected ? 'selected' : ''}`}>
      <div className="visual-editor-node-header">
        <div 
          className="visual-editor-node-color" 
          style={{ backgroundColor: color }}
        />
        <span className="visual-editor-node-name">{group.name}</span>
      </div>
      <div className="visual-editor-node-body">
        <div className="visual-editor-node-meta">
          <span className="visual-editor-node-replicas">
            {group.replicas} {group.replicas === 1 ? 'replica' : 'replicas'}
          </span>
        </div>
        {group.labels?.role && (
          <div className="visual-editor-node-role">
            <span className="visual-editor-node-role-label">role:</span>
            <span className="visual-editor-node-role-value">{group.labels.role}</span>
          </div>
        )}
      </div>
    </div>
  );
}

// ============================================================================
// Main Component
// ============================================================================

function VisualEditor({
  nodeGroups,
  selectedGroupId,
  onSelectGroup,
  onAddGroup,
}: VisualEditorProps) {
  // Transform groups to React Flow nodes with custom labels
  const initialNodes = useMemo(() => {
    const nodes = transformGroupsToNodes(nodeGroups, selectedGroupId);
    return nodes.map((node) => ({
      ...node,
      data: {
        label: (
          <NodeLabel
            group={node.data.group}
            isSelected={node.data.isSelected}
            color={node.data.color}
          />
        ),
      },
    }));
  }, [nodeGroups, selectedGroupId]);

  // Apply layout
  const layoutedNodes = useMemo(
    () => getLayoutedNodes(initialNodes),
    [initialNodes]
  );

  const [nodes, setNodes, onNodesChange] = useNodesState(layoutedNodes);

  // Update nodes when props change
  useEffect(() => {
    setNodes(layoutedNodes);
  }, [layoutedNodes, setNodes]);

  // Handle node click
  const handleNodeClick = useCallback(
    (_event: React.MouseEvent, node: Node) => {
      onSelectGroup(node.id);
    },
    [onSelectGroup]
  );

  // Handle pane click (deselect)
  const handlePaneClick = useCallback(() => {
    // Deselect by calling with empty string or handle in parent
    // For now, we don't deselect on pane click to match expected UX
  }, []);

  // Prevent node dragging
  const handleNodesChange: OnNodesChange = useCallback(
    (changes) => {
      // Filter out position changes to prevent dragging
      const filteredChanges = changes.filter((change) => change.type !== 'position');
      onNodesChange(filteredChanges);
    },
    [onNodesChange]
  );

  return (
    <div className="visual-editor">
      <div className="visual-editor-canvas">
        <ReactFlow
          nodes={nodes}
          edges={[]}
          onNodesChange={handleNodesChange}
          onNodeClick={handleNodeClick}
          onPaneClick={handlePaneClick}
          fitView
          defaultViewport={DEFAULT_VIEWPORT}
          minZoom={0.3}
          maxZoom={1.5}
          attributionPosition="bottom-left"
          proOptions={{ hideAttribution: true }}
          nodesDraggable={false}
          nodesConnectable={false}
          elementsSelectable={true}
        >
          <Background gap={20} size={1} color="#374151" />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div>

      <div className="visual-editor-footer">
        <button
          className="visual-editor-add-btn"
          onClick={onAddGroup}
          title="Add a new node group"
        >
          <span className="visual-editor-add-icon">+</span>
          <span className="visual-editor-add-text">Add Node Group</span>
        </button>
        <div className="visual-editor-hint">
          {nodeGroups.length === 0 ? (
            <span>Start by adding a node group</span>
          ) : (
            <span>Click a group to select and edit</span>
          )}
        </div>
      </div>
    </div>
  );
}

export default memo(VisualEditor);
