import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import NodeConfigPanel from './NodeConfigPanel';
import type { TopologyNode } from '../../types/api';

// ============================================================================
// Test Data
// ============================================================================

const mockNode: TopologyNode = {
  id: 'node-1',
  name: 'drone-1',
  role: 'drone',
  ip: '10.0.0.1',
  labels: { role: 'drone', app: 'test' },
  status: 'pending',
  groupId: '',
};

// ============================================================================
// Tests
// ============================================================================

describe('NodeConfigPanel', () => {
  it('renders empty state when no node is selected', () => {
    render(<NodeConfigPanel node={null} />);
    
    expect(screen.getByText('Select a node to configure')).toBeInTheDocument();
    expect(screen.getByText('⚙️')).toBeInTheDocument();
  });

  it('renders node configuration when node is selected', () => {
    render(<NodeConfigPanel node={mockNode} />);
    
    expect(screen.getByText('Node Configuration')).toBeInTheDocument();
    expect(screen.getByDisplayValue('drone-1')).toBeInTheDocument();
    expect(screen.getAllByText('Drone').length).toBeGreaterThan(0);
  });

  it('displays node role correctly', () => {
    render(<NodeConfigPanel node={mockNode} />);
    
    expect(screen.getAllByText('Drone').length).toBeGreaterThan(0);
    expect(screen.getByText(/ID: node-1/)).toBeInTheDocument();
  });

  it('displays existing labels', () => {
    render(<NodeConfigPanel node={mockNode} />);
    
    expect(screen.getByText('role')).toBeInTheDocument();
    expect(screen.getByText('app')).toBeInTheDocument();
  });

  it('allows adding new labels', () => {
    const onConfigChange = vi.fn();
    render(<NodeConfigPanel node={mockNode} onConfigChange={onConfigChange} />);
    
    const keyInput = screen.getByPlaceholderText('Key');
    const valueInput = screen.getByPlaceholderText('Value');
    const addButton = screen.getByText('Add');
    
    fireEvent.change(keyInput, { target: { value: 'env' } });
    fireEvent.change(valueInput, { target: { value: 'production' } });
    fireEvent.click(addButton);
    
    expect(screen.getByText('env')).toBeInTheDocument();
    expect(screen.getByText('production')).toBeInTheDocument();
  });

  it('allows removing labels', () => {
    render(<NodeConfigPanel node={mockNode} />);
    
    // Find remove button for 'app' label (second one)
    const removeButtons = screen.getAllByTitle('Remove label');
    fireEvent.click(removeButtons[1]);
    
    // The 'app' label value should be removed (but key might still be visible elsewhere)
    expect(screen.queryByText('test')).not.toBeInTheDocument();
  });

  it('validates required fields', () => {
    render(<NodeConfigPanel node={mockNode} />);
    
    const nameInput = screen.getByDisplayValue('drone-1');
    fireEvent.change(nameInput, { target: { value: '' } });
    
    expect(screen.getByText('Name is required')).toBeInTheDocument();
  });

  it('validates name format', () => {
    render(<NodeConfigPanel node={mockNode} />);
    
    const nameInput = screen.getByDisplayValue('drone-1');
    fireEvent.change(nameInput, { target: { value: 'Invalid Name!' } });
    
    expect(screen.getByText('Name must be lowercase alphanumeric with hyphens')).toBeInTheDocument();
  });

  it('shows unsaved changes indicator', () => {
    render(<NodeConfigPanel node={mockNode} />);
    
    const nameInput = screen.getByDisplayValue('drone-1');
    fireEvent.change(nameInput, { target: { value: 'new-name' } });
    
    expect(screen.getByText('You have unsaved changes')).toBeInTheDocument();
  });

  it('calls onConfigChange when Apply is clicked', () => {
    const onConfigChange = vi.fn();
    render(<NodeConfigPanel node={mockNode} onConfigChange={onConfigChange} />);
    
    const nameInput = screen.getByDisplayValue('drone-1');
    fireEvent.change(nameInput, { target: { value: 'new-drone' } });
    
    const applyButton = screen.getByText('Apply Changes');
    fireEvent.click(applyButton);
    
    expect(onConfigChange).toHaveBeenCalledWith('node-1', expect.objectContaining({
      name: 'new-drone',
    }));
  });

  it('calls onDelete when Delete Node is clicked', () => {
    const onDelete = vi.fn();
    render(<NodeConfigPanel node={mockNode} onDelete={onDelete} />);
    
    const deleteButton = screen.getByText('Delete Node');
    fireEvent.click(deleteButton);
    
    expect(onDelete).toHaveBeenCalledWith('node-1');
  });

  it('calls onClose when close button is clicked', () => {
    const onClose = vi.fn();
    render(<NodeConfigPanel node={mockNode} onClose={onClose} />);
    
    const closeButton = screen.getByTitle('Close');
    fireEvent.click(closeButton);
    
    expect(onClose).toHaveBeenCalled();
  });

  it('allows updating image', () => {
    render(<NodeConfigPanel node={mockNode} />);
    
    const imageInput = screen.getByPlaceholderText('e.g., nginx:alpine');
    fireEvent.change(imageInput, { target: { value: 'custom/image:v1' } });
    
    expect(imageInput).toHaveValue('custom/image:v1');
  });

  it('allows updating replicas', () => {
    render(<NodeConfigPanel node={mockNode} />);
    
    const replicasInput = screen.getByDisplayValue('1');
    fireEvent.change(replicasInput, { target: { value: '3' } });
    
    // For number inputs, the value is returned as number
    expect(replicasInput).toHaveValue(3);
  });

  it('allows setting resources', () => {
    render(<NodeConfigPanel node={mockNode} />);
    
    const cpuInput = screen.getByPlaceholderText('e.g., 100m, 0.5');
    const memoryInput = screen.getByPlaceholderText('e.g., 128Mi, 1Gi');
    
    fireEvent.change(cpuInput, { target: { value: '500m' } });
    fireEvent.change(memoryInput, { target: { value: '256Mi' } });
    
    expect(cpuInput).toHaveValue('500m');
    expect(memoryInput).toHaveValue('256Mi');
  });

  it('disables Apply button when no changes', () => {
    render(<NodeConfigPanel node={mockNode} />);
    
    const applyButton = screen.getByText('Apply Changes');
    expect(applyButton).toBeDisabled();
  });

  it('disables Apply button when there are validation errors', () => {
    render(<NodeConfigPanel node={mockNode} />);
    
    const nameInput = screen.getByDisplayValue('drone-1');
    fireEvent.change(nameInput, { target: { value: '' } });
    
    const applyButton = screen.getByText('Apply Changes');
    expect(applyButton).toBeDisabled();
  });
});
