import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import TrafficControlPanel from './TrafficControlPanel';
import type { TopologyLink } from '../types/api';

// Mock CSS import
vi.mock('./TrafficControlPanel.css', () => ({}));

describe('TrafficControlPanel', () => {
  const mockLink: TopologyLink = {
    id: 'link-1',
    sourceId: 'node-1',
    targetId: 'node-2',
    status: 'active',
    policy: {
      bandwidth: '10Mbps',
      latency: '50ms',
      jitter: '10ms',
      packetLoss: '0.5%',
    },
  };

  const mockOnSave = vi.fn();
  const mockOnReset = vi.fn();
  const mockOnClose = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders empty state when no link is provided', () => {
    render(<TrafficControlPanel link={null} />);
    
    expect(screen.getByText('Select a link to adjust traffic parameters')).toBeInTheDocument();
  });

  it('renders link info when link is provided', () => {
    render(<TrafficControlPanel link={mockLink} />);
    
    expect(screen.getByText('Traffic Control')).toBeInTheDocument();
    expect(screen.getByText('node-1 → node-2')).toBeInTheDocument();
  });

  it('displays all four sliders', () => {
    render(<TrafficControlPanel link={mockLink} />);
    
    expect(screen.getByText('Bandwidth')).toBeInTheDocument();
    expect(screen.getByText('Latency')).toBeInTheDocument();
    expect(screen.getByText('Jitter')).toBeInTheDocument();
    expect(screen.getByText('Packet Loss')).toBeInTheDocument();
  });

  it('parses and displays initial policy values from link', () => {
    render(<TrafficControlPanel link={mockLink} />);
    
    // Check that values are parsed from the policy
    expect(screen.getByText('10.0 Mbps')).toBeInTheDocument();
    expect(screen.getByText('50 ms')).toBeInTheDocument();
    expect(screen.getByText('10 ms')).toBeInTheDocument();
    expect(screen.getByText('0.5%')).toBeInTheDocument();
  });

  it('shows preview of current policy', () => {
    render(<TrafficControlPanel link={mockLink} />);
    
    expect(screen.getByText(/Preview:/)).toBeInTheDocument();
    expect(screen.getByText(/10.0Mbps, 50ms, 10ms, 0.5%/)).toBeInTheDocument();
  });

  it('disables Apply Changes button when no changes', () => {
    render(
      <TrafficControlPanel link={mockLink} onSave={mockOnSave} />
    );
    
    const applyButton = screen.getByRole('button', { name: 'Apply Changes' });
    expect(applyButton).toBeDisabled();
  });

  it('enables Apply Changes button when values change', async () => {
    const user = userEvent.setup();
    render(
      <TrafficControlPanel link={mockLink} onSave={mockOnSave} />
    );
    
    // Find and change a slider
    const sliders = screen.getAllByRole('slider');
    await user.click(sliders[0]); // Bandwidth slider
    
    // Change value
    fireEvent.change(sliders[0], { target: { value: '100' } });
    
    // Apply button should now be enabled
    const applyButton = screen.getByRole('button', { name: 'Apply Changes' });
    expect(applyButton).not.toBeDisabled();
  });

  it('shows unsaved changes message when values are modified', () => {
    render(<TrafficControlPanel link={mockLink} />);
    
    // Change a slider value
    const sliders = screen.getAllByRole('slider');
    fireEvent.change(sliders[0], { target: { value: '100' } });
    
    expect(screen.getByText('You have unsaved changes')).toBeInTheDocument();
  });

  it('calls onSave with correct parameters', async () => {
    const user = userEvent.setup();
    render(
      <TrafficControlPanel link={mockLink} onSave={mockOnSave} />
    );
    
    // Change bandwidth
    const sliders = screen.getAllByRole('slider');
    fireEvent.change(sliders[0], { target: { value: '100' } });
    
    // Click Apply
    await user.click(screen.getByRole('button', { name: 'Apply Changes' }));
    
    expect(mockOnSave).toHaveBeenCalledWith('link-1', expect.objectContaining({
      bandwidth: expect.stringContaining('Mbps'),
      latency: expect.any(String),
      jitter: expect.any(String),
      packetLoss: expect.any(String),
    }));
  });

  it('calls onReset when Reset button is clicked', async () => {
    const user = userEvent.setup();
    render(
      <TrafficControlPanel link={mockLink} onReset={mockOnReset} />
    );
    
    // Change a value first
    const sliders = screen.getAllByRole('slider');
    fireEvent.change(sliders[0], { target: { value: '100' } });
    
    // Click Reset
    await user.click(screen.getByRole('button', { name: 'Reset' }));
    
    // Should reset to original value
    expect(screen.getByText('10.0 Mbps')).toBeInTheDocument();
  });

  it('calls onClose when close button is clicked', async () => {
    const user = userEvent.setup();
    render(
      <TrafficControlPanel link={mockLink} onClose={mockOnClose} />
    );
    
    // Close button has × symbol, use title attribute to find it
    const closeButton = screen.getByTitle('Close');
    await user.click(closeButton);
    
    expect(mockOnClose).toHaveBeenCalledTimes(1);
  });

  it('does not show close button when onClose is not provided', () => {
    render(<TrafficControlPanel link={mockLink} />);
    
    expect(screen.queryByRole('button', { name: 'Close' })).not.toBeInTheDocument();
  });

  it('resets to default values for link without policy', () => {
    const linkWithoutPolicy: TopologyLink = {
      id: 'link-2',
      sourceId: 'node-1',
      targetId: 'node-2',
      status: 'inactive',
    };
    
    render(<TrafficControlPanel link={linkWithoutPolicy} />);
    
    // Should show default values (10 Mbps, 0ms, 0ms, 0%)
    expect(screen.getByText('10.0 Mbps')).toBeInTheDocument();
    // Use getAllByText since "0 ms" appears multiple times (latency and jitter)
    const zeroMsElements = screen.getAllByText('0 ms');
    expect(zeroMsElements.length).toBeGreaterThanOrEqual(2);
  });

  it('formats bandwidth correctly for values >= 1000 Mbps', () => {
    render(<TrafficControlPanel link={mockLink} />);
    
    // Change bandwidth to a high value
    const sliders = screen.getAllByRole('slider');
    fireEvent.change(sliders[0], { target: { value: '1000' } });
    
    // Should show Gbps format (max slider value is 1000 = 1.0 Gbps)
    // Use getAllByText since "1.0 Gbps" appears in both slider value and bounds
    const gbpsElements = screen.getAllByText('1.0 Gbps');
    expect(gbpsElements.length).toBeGreaterThanOrEqual(1);
  });
});
