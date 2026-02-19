import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import TopologyEditor from './TopologyEditor';
import type { Node, Edge } from 'reactflow';
import { useState } from 'react';

// Mock ReactFlow
vi.mock('reactflow', () => {
  interface MockReactFlowProps {
    nodes: Array<{ id: string; data: unknown }>;
    edges: Array<{ id: string; source: string; target: string; data?: unknown }>;
    onNodesChange?: (changes: unknown) => void;
    onEdgesChange?: (changes: unknown) => void;
    onConnect?: (connection: unknown) => void;
    onNodeClick?: (e: React.MouseEvent, node: unknown) => void;
    onEdgeClick?: (e: React.MouseEvent, edge: unknown) => void;
    onPaneClick?: () => void;
    onDragOver?: (e: React.DragEvent) => void;
    onDrop?: (e: React.DragEvent) => void;
    children: React.ReactNode;
    nodeTypes?: Record<string, unknown>;
    deleteKeyCode?: string | null;
  }

  const MockReactFlow = ({
    nodes,
    edges,
    onNodeClick,
    onEdgeClick,
    onPaneClick,
    onConnect,
    children,
  }: MockReactFlowProps) => (
    <div data-testid="react-flow" data-nodes={nodes.length} data-edges={edges.length}>
      {nodes.map((node) => (
        <div
          key={node.id}
          data-testid={`node-${node.id}`}
          onClick={(e) => onNodeClick?.(e, node)}
        >
          Node {node.id}
        </div>
      ))}
      {edges.map((edge) => (
        <div
          key={edge.id}
          data-testid={`edge-${edge.id}`}
          data-source={edge.source}
          data-target={edge.target}
          onClick={(e) => onEdgeClick?.(e, edge)}
        >
          Edge {edge.id}
        </div>
      ))}
      <button
        data-testid="connect-button"
        onClick={() => {
          const source = nodes[0]?.id;
          const target = nodes[1]?.id;
          if (source && target && onConnect) {
            onConnect({ source, target });
          }
        }}
      >
        Connect
      </button>
      <div data-testid="pane" onClick={onPaneClick}>
        Pane
      </div>
      {children}
    </div>
  );

  return {
    default: MockReactFlow,
    ReactFlow: MockReactFlow,
    Background: () => <div data-testid="background" />,
    Controls: () => <div data-testid="controls" />,
    MiniMap: () => <div data-testid="minimap" />,
    Panel: ({ children }: { children: React.ReactNode }) => (
      <div data-testid="panel">{children}</div>
    ),
    useNodesState: (initial: unknown[]) => {
      const [nodes, setNodes] = useState(initial);
      const onNodesChange = vi.fn();
      return [nodes, setNodes, onNodesChange];
    },
    useEdgesState: (initial: unknown[]) => {
      const [edges, setEdges] = useState(initial);
      const onEdgesChange = vi.fn();
      return [edges, setEdges, onEdgesChange];
    },
    addEdge: vi.fn((edge, edges) => [...edges, edge]),
    MarkerType: { ArrowClosed: 'arrowClosed' },
    SelectionMode: { Partial: 1, Full: 2 },
  };
});

// Mock NodeCard
vi.mock('../components/topology/NodeCard', () => ({
  default: () => <div data-testid="node-card" />,
}));

// Mock NodePalette
vi.mock('../components/topology/NodePalette', () => ({
  default: ({ collapsed }: { collapsed: boolean }) => (
    <div data-testid="node-palette" data-collapsed={collapsed}>
      Palette
    </div>
  ),
}));

// Mock NodeConfigPanel
vi.mock('../components/topology/NodeConfigPanel', () => ({
  default: ({ node }: { node: unknown }) => (
    <div data-testid="node-config-panel">{node ? 'Config Panel' : 'No Selection'}</div>
  ),
}));

// Mock CSS import
vi.mock('./TopologyEditor.css', () => ({}));

// Mock topologyConverter to return no errors
vi.mock('../utils/topologyConverter', () => ({
  editorStateToYaml: () => ({
    yaml: 'mock: yaml',
    errors: [],
    warnings: [],
  }),
}));

// Mock YamlPreviewDialog
vi.mock('../components/topology/YamlPreviewDialog', () => ({
  default: ({ isOpen, onSave, onClose }: { isOpen: boolean; onSave?: () => void; onClose: () => void }) => {
    if (!isOpen) return null;
    return (
      <div data-testid="yaml-preview-dialog">
        <button data-testid="dialog-save-button" onClick={() => { onSave?.(); onClose(); }}>
          Save
        </button>
        <button data-testid="dialog-close-button" onClick={onClose}>
          Close
        </button>
      </div>
    );
  },
}));

describe('TopologyEditor', () => {
  const mockOnSave = vi.fn();
  const mockOnCancel = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('renders without crashing', () => {
    render(<TopologyEditor />);
    expect(screen.getByTestId('react-flow')).toBeInTheDocument();
  });

  it('renders with empty nodes and edges', () => {
    render(<TopologyEditor />);
    expect(screen.getByTestId('react-flow')).toHaveAttribute('data-nodes', '0');
    expect(screen.getByTestId('react-flow')).toHaveAttribute('data-edges', '0');
  });

  it('renders toolbar buttons', () => {
    render(<TopologyEditor onCancel={mockOnCancel} />);
    expect(screen.getByText('Cancel')).toBeInTheDocument();
    expect(screen.getByText('Delete')).toBeInTheDocument();
    expect(screen.getByText('Save Topology')).toBeInTheDocument();
  });

  it('Delete button is disabled when nothing is selected', () => {
    render(<TopologyEditor />);
    const deleteButton = screen.getByText('Delete');
    expect(deleteButton).toBeDisabled();
  });

  it('calls onCancel when Cancel button is clicked', () => {
    render(<TopologyEditor onCancel={mockOnCancel} />);
    const cancelButton = screen.getByText('Cancel');
    fireEvent.click(cancelButton);
    expect(mockOnCancel).toHaveBeenCalledTimes(1);
  });

  it('renders NodePalette in sidebar', () => {
    render(<TopologyEditor />);
    expect(screen.getByTestId('node-palette')).toBeInTheDocument();
  });

  it('renders NodeConfigPanel in config area', () => {
    render(<TopologyEditor />);
    expect(screen.getByTestId('node-config-panel')).toBeInTheDocument();
  });

  it('handles keyboard delete for edges', async () => {
    // Render with initial edge
    const initialEdges = [
      {
        id: 'edge-1',
        source: 'node-1',
        target: 'node-2',
        type: 'smoothstep',
        animated: true,
        markerEnd: { type: 'arrowClosed', color: '#94a3b8' },
        style: { stroke: '#94a3b8', strokeWidth: 1.5 },
        data: { policy: { bandwidth: '10Mbps', latency: '5ms', jitter: '1ms', packetLoss: '0.1%' } },
      },
    ];

    render(<TopologyEditor initialEdges={initialEdges as unknown as Edge[]} />);

    // Click on the edge to select it
    const edge = screen.getByTestId('edge-edge-1');
    fireEvent.click(edge);

    // Press Delete key
    fireEvent.keyDown(window, { key: 'Delete' });

    // Edge should be deleted
    await waitFor(() => {
      const reactFlow = screen.getByTestId('react-flow');
      expect(reactFlow).toHaveAttribute('data-edges', '0');
    });
  });

  it('handles keyboard delete for nodes', async () => {
    // Render with initial nodes
    const initialNodes = [
      {
        id: 'node-1',
        type: 'custom',
        position: { x: 0, y: 0 },
        data: {
          node: {
            id: 'node-1',
            name: 'Test Node',
            role: 'drone',
            ip: '10.0.0.1',
            labels: {},
            status: 'pending',
            groupId: '',
          },
          isSelected: false,
        },
      },
    ];

    render(<TopologyEditor initialNodes={initialNodes as unknown as Node[]} />);

    // Click on the node to select it
    const node = screen.getByTestId('node-node-1');
    fireEvent.click(node);

    // Press Delete key
    fireEvent.keyDown(window, { key: 'Delete' });

    // Node should be deleted
    await waitFor(() => {
      const reactFlow = screen.getByTestId('react-flow');
      expect(reactFlow).toHaveAttribute('data-nodes', '0');
    });
  });

  it('handles Backspace key for deletion', async () => {
    // Render with initial edge
    const initialEdges = [
      {
        id: 'edge-1',
        source: 'node-1',
        target: 'node-2',
        type: 'smoothstep',
        animated: true,
        markerEnd: { type: 'arrowClosed', color: '#94a3b8' },
        style: { stroke: '#94a3b8', strokeWidth: 1.5 },
        data: { policy: { bandwidth: '10Mbps', latency: '5ms', jitter: '1ms', packetLoss: '0.1%' } },
      },
    ];

    render(<TopologyEditor initialEdges={initialEdges as unknown as Edge[]} />);

    // Click on the edge to select it
    const edge = screen.getByTestId('edge-edge-1');
    fireEvent.click(edge);

    // Press Backspace key
    fireEvent.keyDown(window, { key: 'Backspace' });

    // Edge should be deleted
    await waitFor(() => {
      const reactFlow = screen.getByTestId('react-flow');
      expect(reactFlow).toHaveAttribute('data-edges', '0');
    });
  });

  it('calls onSave when Save button is clicked', async () => {
    render(<TopologyEditor onSave={mockOnSave} />);
    
    // Click Save Topology button to open preview dialog
    const saveButton = screen.getByText('Save Topology');
    fireEvent.click(saveButton);
    
    // Dialog should open
    expect(screen.getByTestId('yaml-preview-dialog')).toBeInTheDocument();
    
    // Click Save in dialog
    const dialogSaveButton = screen.getByTestId('dialog-save-button');
    fireEvent.click(dialogSaveButton);
    
    // onSave should be called
    expect(mockOnSave).toHaveBeenCalledTimes(1);
  });

  it('handles pane click to deselect', () => {
    render(<TopologyEditor />);

    // Click pane
    const pane = screen.getByTestId('pane');
    fireEvent.click(pane);

    // Delete button should still be disabled
    const deleteButton = screen.getByText('Delete');
    expect(deleteButton).toBeDisabled();
  });

  // ========================================
  // Link Drawing Tests (LC-003)
  // ========================================

  it('creates a new edge when onConnect is called', async () => {
    // Render with two nodes
    const initialNodes = [
      {
        id: 'node-1',
        type: 'custom',
        position: { x: 0, y: 0 },
        data: {
          node: {
            id: 'node-1',
            name: 'Source Node',
            role: 'drone',
            ip: '10.0.0.1',
            labels: {},
            status: 'pending',
            groupId: '',
          },
          isSelected: false,
        },
      },
      {
        id: 'node-2',
        type: 'custom',
        position: { x: 200, y: 0 },
        data: {
          node: {
            id: 'node-2',
            name: 'Target Node',
            role: 'server',
            ip: '10.0.0.2',
            labels: {},
            status: 'pending',
            groupId: '',
          },
          isSelected: false,
        },
      },
    ];

    render(<TopologyEditor initialNodes={initialNodes as unknown as Node[]} />);

    // Initially no edges
    expect(screen.getByTestId('react-flow')).toHaveAttribute('data-edges', '0');

    // Click connect button (simulates dragging from source handle to target handle)
    const connectButton = screen.getByTestId('connect-button');
    fireEvent.click(connectButton);

    // Edge should be created
    await waitFor(() => {
      expect(screen.getByTestId('react-flow')).toHaveAttribute('data-edges', '1');
    });

    // Verify the edge was created between the two nodes
    const edge = screen.getByTestId('edge-edge-node-1-node-2');
    expect(edge).toHaveAttribute('data-source', 'node-1');
    expect(edge).toHaveAttribute('data-target', 'node-2');
  });

  it('prevents duplicate edges between same nodes', async () => {
    // Render with two nodes and an existing edge
    const initialNodes = [
      {
        id: 'node-1',
        type: 'custom',
        position: { x: 0, y: 0 },
        data: {
          node: { id: 'node-1', name: 'Node 1', role: 'drone', ip: '10.0.0.1', labels: {}, status: 'pending', groupId: '' },
          isSelected: false,
        },
      },
      {
        id: 'node-2',
        type: 'custom',
        position: { x: 200, y: 0 },
        data: {
          node: { id: 'node-2', name: 'Node 2', role: 'server', ip: '10.0.0.2', labels: {}, status: 'pending', groupId: '' },
          isSelected: false,
        },
      },
    ];

    const initialEdges = [
      {
        id: 'edge-node-1-node-2',
        source: 'node-1',
        target: 'node-2',
        type: 'smoothstep',
        animated: true,
        markerEnd: { type: 'arrowClosed', color: '#94a3b8' },
        style: { stroke: '#94a3b8', strokeWidth: 1.5 },
        data: { policy: { bandwidth: '10Mbps', latency: '5ms', jitter: '1ms', packetLoss: '0.1%' } },
      },
    ];

    render(
      <TopologyEditor
        initialNodes={initialNodes as unknown as Node[]}
        initialEdges={initialEdges as unknown as Edge[]}
      />
    );

    // One edge exists
    expect(screen.getByTestId('react-flow')).toHaveAttribute('data-edges', '1');

    // Try to connect again
    const connectButton = screen.getByTestId('connect-button');
    fireEvent.click(connectButton);

    // Should still be 1 edge (duplicate prevented)
    await waitFor(() => {
      expect(screen.getByTestId('react-flow')).toHaveAttribute('data-edges', '1');
    });
  });

  it('selects newly created edge', async () => {
    const initialNodes = [
      {
        id: 'node-1',
        type: 'custom',
        position: { x: 0, y: 0 },
        data: {
          node: { id: 'node-1', name: 'Node 1', role: 'drone', ip: '10.0.0.1', labels: {}, status: 'pending', groupId: '' },
          isSelected: false,
        },
      },
      {
        id: 'node-2',
        type: 'custom',
        position: { x: 200, y: 0 },
        data: {
          node: { id: 'node-2', name: 'Node 2', role: 'server', ip: '10.0.0.2', labels: {}, status: 'pending', groupId: '' },
          isSelected: false,
        },
      },
    ];

    render(<TopologyEditor initialNodes={initialNodes as unknown as Node[]} />);

    // Create edge
    const connectButton = screen.getByTestId('connect-button');
    fireEvent.click(connectButton);

    // Wait for edge to be created and selected
    await waitFor(() => {
      // Delete button should be enabled (edge is selected)
      const deleteButton = screen.getByText('Delete');
      expect(deleteButton).not.toBeDisabled();
    });
  });

  it('deletes connected edges when node is deleted', async () => {
    const initialNodes = [
      {
        id: 'node-1',
        type: 'custom',
        position: { x: 0, y: 0 },
        data: {
          node: { id: 'node-1', name: 'Node 1', role: 'drone', ip: '10.0.0.1', labels: {}, status: 'pending', groupId: '' },
          isSelected: false,
        },
      },
      {
        id: 'node-2',
        type: 'custom',
        position: { x: 200, y: 0 },
        data: {
          node: { id: 'node-2', name: 'Node 2', role: 'server', ip: '10.0.0.2', labels: {}, status: 'pending', groupId: '' },
          isSelected: false,
        },
      },
    ];

    const initialEdges = [
      {
        id: 'edge-node-1-node-2',
        source: 'node-1',
        target: 'node-2',
        type: 'smoothstep',
        animated: true,
        markerEnd: { type: 'arrowClosed', color: '#94a3b8' },
        style: { stroke: '#94a3b8', strokeWidth: 1.5 },
        data: { policy: { bandwidth: '10Mbps', latency: '5ms', jitter: '1ms', packetLoss: '0.1%' } },
      },
    ];

    render(
      <TopologyEditor
        initialNodes={initialNodes as unknown as Node[]}
        initialEdges={initialEdges as unknown as Edge[]}
      />
    );

    // Select node-1
    const node1 = screen.getByTestId('node-node-1');
    fireEvent.click(node1);

    // Delete node-1
    fireEvent.keyDown(window, { key: 'Delete' });

    // Both node and connected edge should be deleted
    await waitFor(() => {
      expect(screen.getByTestId('react-flow')).toHaveAttribute('data-nodes', '1');
      expect(screen.getByTestId('react-flow')).toHaveAttribute('data-edges', '0');
    });
  });
});
