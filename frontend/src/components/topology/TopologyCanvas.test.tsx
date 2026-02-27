import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import TopologyCanvas from './TopologyCanvas';
import type { TopologyNode, TopologyLink } from '../../types/api';

// Mock ReactFlow since it requires complex DOM setup
vi.mock('reactflow', () => {
  interface MockReactFlowProps {
    nodes: Array<{ id: string; data: { node: { name: string } } }>;
    edges: Array<{ id: string; data?: { link: { sourceId: string } } }>;
    onNodeClick?: (e: React.MouseEvent, node: unknown) => void;
    onEdgeClick?: (e: React.MouseEvent, edge: unknown) => void;
    children: React.ReactNode;
  }

  const MockReactFlow = ({ nodes, edges, onNodeClick, onEdgeClick, children }: MockReactFlowProps) => (
    <div data-testid="react-flow" data-nodes={nodes.length} data-edges={edges.length}>
      {nodes.map((node) => (
        <div
          key={node.id}
          data-testid={`node-${node.id}`}
          onClick={(e) => onNodeClick?.(e, node)}
        >
          {node.data.node.name}
        </div>
      ))}
      {edges.map((edge) => (
        <div
          key={edge.id}
          data-testid={`edge-${edge.id}`}
          onClick={(e) => onEdgeClick?.(e, edge)}
        >
          Edge {edge.id}
        </div>
      ))}
      {children}
    </div>
  );
  
  return {
    default: MockReactFlow,
    ReactFlow: MockReactFlow,
    Background: () => <div data-testid="background" />,
    Controls: () => <div data-testid="controls" />,
    MiniMap: () => <div data-testid="minimap" />,
    useNodesState: (initial: unknown[]) => [initial, vi.fn(), vi.fn()],
    useEdgesState: (initial: unknown[]) => [initial, vi.fn(), vi.fn()],
    MarkerType: { ArrowClosed: 'arrowClosed' },
  };
});

// Mock dagre layout
vi.mock('dagre', () => ({
  default: {
    graphlib: {
      Graph: class {
        nodes: string[] = [];
        edges: [string, string][] = [];
        nodeData: Record<string, { x: number; y: number }> = {};
        
        setGraph() {}
        setDefaultEdgeLabel() {}
        setNode(id: string) { this.nodes.push(id); }
        setEdge(from: string, to: string) { this.edges.push([from, to]); }
        node(id: string) { return this.nodeData[id] || { x: 0, y: 0 }; }
      },
    },
    layout: vi.fn(),
  },
}));

// Mock NodeCard
vi.mock('./NodeCard', () => ({
  default: () => <div data-testid="node-card" />,
}));

// Mock CSS import
vi.mock('./TopologyCanvas.css', () => ({}));

describe('TopologyCanvas', () => {
  const mockNodes: TopologyNode[] = [
    {
      id: 'node-1',
      name: 'Node 1',
      ip: '10.0.0.1',
      role: 'drone',
      status: 'running',
      labels: { app: 'kuro' },
      groupId: 'group-1',
    },
    {
      id: 'node-2',
      name: 'Node 2',
      ip: '10.0.0.2',
      role: 'ground-station',
      status: 'running',
      labels: { app: 'kuro' },
      groupId: 'group-1',
    },
  ];

  const mockLinks: TopologyLink[] = [
    {
      id: 'link-1',
      sourceId: 'node-1',
      targetId: 'node-2',
      status: 'active',
      policy: {
        bandwidth: '10Mbps',
        latency: '5ms',
        jitter: '1ms',
        packetLoss: '0.1%',
      },
    },
  ];

  const mockOnNodeClick = vi.fn();
  const mockOnEdgeClick = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders without crashing', () => {
    render(
      <TopologyCanvas nodes={mockNodes} links={mockLinks} />
    );
    expect(screen.getByTestId('react-flow')).toBeInTheDocument();
  });

  it('displays the correct number of nodes', () => {
    render(
      <TopologyCanvas nodes={mockNodes} links={mockLinks} />
    );
    expect(screen.getByTestId('react-flow')).toHaveAttribute('data-nodes', '2');
  });

  it('displays the correct number of edges', () => {
    render(
      <TopologyCanvas nodes={mockNodes} links={mockLinks} />
    );
    expect(screen.getByTestId('react-flow')).toHaveAttribute('data-edges', '1');
  });

  it('renders with empty nodes and links', () => {
    render(
      <TopologyCanvas nodes={[]} links={[]} />
    );
    expect(screen.getByTestId('react-flow')).toHaveAttribute('data-nodes', '0');
    expect(screen.getByTestId('react-flow')).toHaveAttribute('data-edges', '0');
  });

  it('calls onNodeClick when a node is clicked', () => {
    render(
      <TopologyCanvas
        nodes={mockNodes}
        links={mockLinks}
        onNodeClick={mockOnNodeClick}
      />
    );
    
    const nodeElement = screen.getByTestId('node-node-1');
    fireEvent.click(nodeElement);
    
    expect(mockOnNodeClick).toHaveBeenCalledTimes(1);
    expect(mockOnNodeClick).toHaveBeenCalledWith(mockNodes[0]);
  });

  it('calls onEdgeClick when an edge is clicked', () => {
    render(
      <TopologyCanvas
        nodes={mockNodes}
        links={mockLinks}
        onEdgeClick={mockOnEdgeClick}
      />
    );
    
    const edgeElement = screen.getByTestId('edge-link-1');
    fireEvent.click(edgeElement);
    
    expect(mockOnEdgeClick).toHaveBeenCalledTimes(1);
  });

  it('applies custom className', () => {
    render(
      <TopologyCanvas
        nodes={mockNodes}
        links={mockLinks}
        className="custom-class"
      />
    );
    
    const canvas = screen.getByTestId('react-flow').parentElement;
    expect(canvas).toHaveClass('topology-canvas');
    expect(canvas).toHaveClass('custom-class');
  });

  it('renders Background, Controls, and MiniMap by default', () => {
    render(
      <TopologyCanvas nodes={mockNodes} links={mockLinks} />
    );
    
    expect(screen.getByTestId('background')).toBeInTheDocument();
    expect(screen.getByTestId('controls')).toBeInTheDocument();
    expect(screen.getByTestId('minimap')).toBeInTheDocument();
  });

  it('hides MiniMap when showMiniMap is false', () => {
    render(
      <TopologyCanvas nodes={mockNodes} links={mockLinks} showMiniMap={false} />
    );
    
    expect(screen.queryByTestId('minimap')).not.toBeInTheDocument();
  });
});