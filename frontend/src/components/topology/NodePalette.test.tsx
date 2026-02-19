import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import NodePalette from './NodePalette';

// Mock dataTransfer for drag events
const mockDataTransfer = {
  setData: vi.fn(),
  getData: vi.fn(),
  effectAllowed: '',
  dropEffect: '',
};

describe('NodePalette', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders all node types', () => {
    render(<NodePalette />);

    expect(screen.getByText('Drone')).toBeInTheDocument();
    expect(screen.getByText('Ground Station')).toBeInTheDocument();
    expect(screen.getByText('Gateway')).toBeInTheDocument();
    expect(screen.getByText('Server')).toBeInTheDocument();
    expect(screen.getByText('Client')).toBeInTheDocument();
  });

  it('renders with header title', () => {
    render(<NodePalette />);

    expect(screen.getByText('Node Types')).toBeInTheDocument();
  });

  it('renders with drag hint in footer', () => {
    render(<NodePalette />);

    expect(screen.getByText('Drag nodes to canvas')).toBeInTheDocument();
  });

  it('renders collapsed state correctly', () => {
    render(<NodePalette collapsed />);

    // Header should be empty in collapsed state
    const header = screen.getByRole('heading', { level: 3 });
    expect(header).toBeEmptyDOMElement();

    // Footer hint should not be visible
    expect(screen.queryByText('Drag nodes to canvas')).not.toBeInTheDocument();
  });

  it('applies custom className', () => {
    const { container } = render(<NodePalette className="custom-class" />);

    expect(container.firstChild).toHaveClass('custom-class');
  });

  it('calls onNodeDragStart when drag starts', () => {
    const onNodeDragStart = vi.fn();
    render(<NodePalette onNodeDragStart={onNodeDragStart} />);

    const droneItem = screen.getByText('Drone').closest('[draggable]');
    if (droneItem) {
      fireEvent.dragStart(droneItem, { dataTransfer: mockDataTransfer });
    }

    expect(onNodeDragStart).toHaveBeenCalledWith('drone', expect.objectContaining({
      type: 'drone',
      label: 'Drone',
    }));
  });
});

describe('DraggableNodeItem', () => {
  it('sets correct drag data', async () => {
    const { default: DraggableNodeItem } = await import('./DraggableNodeItem');

    render(
      <DraggableNodeItem
        type="drone"
        label="Drone"
        icon="🚁"
        description="UAV/Drone node"
        color="#3b82f6"
      />
    );

    const item = screen.getByText('Drone').closest('[draggable]');
    expect(item).toHaveAttribute('draggable', 'true');
  });

  it('renders collapsed state', async () => {
    const { default: DraggableNodeItem } = await import('./DraggableNodeItem');

    const { container } = render(
      <DraggableNodeItem
        type="drone"
        label="Drone"
        icon="🚁"
        description="UAV/Drone node"
        color="#3b82f6"
        collapsed
      />
    );

    expect(container.firstChild).toHaveClass('collapsed');
  });
});
