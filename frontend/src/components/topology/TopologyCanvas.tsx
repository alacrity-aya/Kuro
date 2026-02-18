import { useCallback, useMemo, useEffect } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  type Node,
  type Edge,
  type OnConnect,
  MarkerType,
} from 'reactflow';
import 'reactflow/dist/style.css';
import dagre from 'dagre';

import type { TopologyNode, TopologyLink } from '../../types/api';
import NodeCard from './NodeCard';
import './TopologyCanvas.css';

// ============================================================================
// Types
// ============================================================================

export interface TopologyCanvasProps {
  nodes: TopologyNode[];
  links: TopologyLink[];
  selectedNodeId?: string;
  selectedLinkId?: string;
  onNodeClick?: (node: TopologyNode) => void;
  onNodeDoubleClick?: (node: TopologyNode) => void;
  onEdgeClick?: (link: TopologyLink) => void;
  onSelectionChange?: (nodeIds: string[], edgeIds: string[]) => void;
  fitView?: boolean;
  showMiniMap?: boolean;
  className?: string;
}

interface CustomNodeData {
  node: TopologyNode;
  isSelected: boolean;
}

interface CustomEdgeData {
  link: TopologyLink;
}

// ============================================================================
// Constants
// ============================================================================

const NODE_TYPES = {
  custom: NodeCard,
};

const DAGRE_CONFIG = {
  rankdir: 'LR' as const,
  nodesep: 80,
  ranksep: 120,
  align: 'UL' as const,
};

const DEFAULT_VIEWPORT = { x: 0, y: 0, zoom: 0.8 };

// ============================================================================
// Layout Algorithm
// ============================================================================

function getLayoutedElements(
  nodes: Node[],
  edges: Edge[],
  direction: 'TB' | 'LR' = 'LR'
): { nodes: Node[]; edges: Edge[] } {
  const dagreGraph = new dagre.graphlib.Graph();
  dagreGraph.setDefaultEdgeLabel(() => ({}));
  
  dagreGraph.setGraph({
    ...DAGRE_CONFIG,
    rankdir: direction,
  });

  nodes.forEach((node) => {
    dagreGraph.setNode(node.id, { width: 160, height: 80 });
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
        x: nodeWithPosition.x - 80,
        y: nodeWithPosition.y - 40,
      },
    };
  });

  return { nodes: layoutedNodes, edges };
}

// ============================================================================
// Data Transformation
// ============================================================================

function transformTopologyNodesToFlowNodes(
  nodes: TopologyNode[],
  selectedNodeId?: string
): Node<CustomNodeData>[] {
  return nodes.map((node) => ({
    id: node.id,
    type: 'custom',
    position: { x: node.x ?? 0, y: node.y ?? 0 },
    data: {
      node,
      isSelected: node.id === selectedNodeId,
    } satisfies CustomNodeData,
  }));
}

function transformTopologyLinksToFlowEdges(
  links: TopologyLink[],
  selectedLinkId?: string
): Edge<CustomEdgeData>[] {
  return links.map((link) => ({
    id: link.id,
    source: link.sourceId,
    target: link.targetId,
    type: 'smoothstep',
    animated: link.status === 'active',
    markerEnd: {
      type: MarkerType.ArrowClosed,
      color: link.id === selectedLinkId ? '#3b82f6' : '#94a3b8',
    },
    style: {
      stroke: link.id === selectedLinkId ? '#3b82f6' : '#94a3b8',
      strokeWidth: link.id === selectedLinkId ? 2 : 1.5,
    },
    label: link.policy ? `${link.policy.bandwidth}` : undefined,
    labelStyle: { fill: '#64748b', fontWeight: 500, fontSize: 10 },
    labelBgStyle: { fill: '#ffffff', fillOpacity: 0.9 },
    labelBgPadding: [4, 2] as [number, number],
    labelBgBorderRadius: 4,
    data: {
      link,
    } satisfies CustomEdgeData,
  }));
}

// ============================================================================
// Component
// ============================================================================

function TopologyCanvas({
  nodes: topologyNodes,
  links: topologyLinks,
  selectedNodeId,
  selectedLinkId,
  onNodeClick,
  onNodeDoubleClick,
  onEdgeClick,
  onSelectionChange,
  fitView = true,
  showMiniMap = true,
  className,
}: TopologyCanvasProps) {
  // Transform topology data to React Flow format
  const initialNodes = useMemo(
    () => transformTopologyNodesToFlowNodes(topologyNodes, selectedNodeId),
    [topologyNodes, selectedNodeId]
  );

  const initialEdges = useMemo(
    () => transformTopologyLinksToFlowEdges(topologyLinks, selectedLinkId),
    [topologyLinks, selectedLinkId]
  );

  // Layout nodes on mount or when data changes
  const { nodes: layoutedNodes, edges: layoutedEdges } = useMemo(() => {
    // Only apply layout if nodes don't have positions
    const needsLayout = topologyNodes.some((n) => n.x === undefined || n.y === undefined);
    if (needsLayout) {
      return getLayoutedElements(initialNodes, initialEdges);
    }
    return { nodes: initialNodes, edges: initialEdges };
  }, [initialNodes, initialEdges, topologyNodes]);

  const [nodes, setNodes, onNodesChange] = useNodesState(layoutedNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(layoutedEdges);

  // Update nodes/edges when props change
  useEffect(() => {
    setNodes(layoutedNodes);
  }, [layoutedNodes, setNodes]);

  useEffect(() => {
    setEdges(layoutedEdges);
  }, [layoutedEdges, setEdges]);

  // Handle node click
  const handleNodeClick = useCallback(
    (_event: React.MouseEvent, node: Node<CustomNodeData>) => {
      onNodeClick?.(node.data.node);
    },
    [onNodeClick]
  );

  // Handle node double click
  const handleNodeDoubleClick = useCallback(
    (_event: React.MouseEvent, node: Node<CustomNodeData>) => {
      onNodeDoubleClick?.(node.data.node);
    },
    [onNodeDoubleClick]
  );

  // Handle edge click
  const handleEdgeClick = useCallback(
    (_event: React.MouseEvent, edge: Edge<CustomEdgeData>) => {
      if (edge.data?.link) {
        onEdgeClick?.(edge.data.link);
      }
    },
    [onEdgeClick]
  );

  // Handle selection change
  const handleSelectionChange = useCallback(
    ({ nodes: selectedNodes, edges: selectedEdges }: { nodes: Node[]; edges: Edge[] }) => {
      onSelectionChange?.(
        selectedNodes.map((n) => n.id),
        selectedEdges.map((e) => e.id)
      );
    },
    [onSelectionChange]
  );

  // Handle connect (for potential future use)
  const onConnect: OnConnect = useCallback(() => {
    // Connection handling - read-only for now
  }, []);

  return (
    <div className={`topology-canvas ${className || ''}`}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        onNodeClick={handleNodeClick}
        onNodeDoubleClick={handleNodeDoubleClick}
        onEdgeClick={handleEdgeClick}
        onSelectionChange={handleSelectionChange}
        nodeTypes={NODE_TYPES}
        fitView={fitView}
        defaultViewport={DEFAULT_VIEWPORT}
        minZoom={0.2}
        maxZoom={2}
        attributionPosition="bottom-left"
        proOptions={{ hideAttribution: true }}
      >
        <Background gap={16} size={1} />
        <Controls showInteractive={false} />
        {showMiniMap && (
          <MiniMap
            nodeColor={(node) => {
              const data = node.data as CustomNodeData | undefined;
              if (data?.node.status === 'running') return '#10b981';
              if (data?.node.status === 'pending') return '#f59e0b';
              if (data?.node.status === 'failed') return '#ef4444';
              return '#6b7280';
            }}
            maskColor="rgba(0, 0, 0, 0.05)"
          />
        )}
      </ReactFlow>
    </div>
  );
}

export default TopologyCanvas;
