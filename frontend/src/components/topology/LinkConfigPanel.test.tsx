import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import LinkConfigPanel from './LinkConfigPanel';
import type { TrafficPolicy } from '../../types/api';

// ============================================================================
// Test Data
// ============================================================================

const mockPolicy: TrafficPolicy = {
  bandwidth: '50Mbps',
  latency: '20ms',
  jitter: '5ms',
  packetLoss: '0.5%',
};

const defaultProps = {
  linkId: 'edge-node-1-node-2',
  sourceName: 'drone-1',
  targetName: 'gateway-1',
  policy: mockPolicy,
  onPolicyChange: vi.fn(),
  onDelete: vi.fn(),
  onClose: vi.fn(),
};

// ============================================================================
// Tests
// ============================================================================

describe('LinkConfigPanel', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // ---------------------------------------------------------------------------
  // Rendering Tests
  // ---------------------------------------------------------------------------

  describe('Rendering', () => {
    it('renders empty state when no link is selected', () => {
      render(<LinkConfigPanel {...defaultProps} linkId={null} policy={null} />);
      
      expect(screen.getByText('Select a link to configure')).toBeInTheDocument();
      expect(screen.getByText('🔗')).toBeInTheDocument();
    });

    it('renders header with title when link is selected', () => {
      render(<LinkConfigPanel {...defaultProps} />);
      
      expect(screen.getByText('Link Configuration')).toBeInTheDocument();
    });

    it('renders link info with source and target names', () => {
      render(<LinkConfigPanel {...defaultProps} />);
      
      expect(screen.getByText('Source:')).toBeInTheDocument();
      expect(screen.getByText('drone-1')).toBeInTheDocument();
      expect(screen.getByText('Target:')).toBeInTheDocument();
      expect(screen.getByText('gateway-1')).toBeInTheDocument();
      expect(screen.getByText('→')).toBeInTheDocument();
    });

    it('renders all four slider labels', () => {
      render(<LinkConfigPanel {...defaultProps} />);
      
      expect(screen.getByText('Bandwidth')).toBeInTheDocument();
      expect(screen.getByText('Latency')).toBeInTheDocument();
      expect(screen.getByText('Jitter')).toBeInTheDocument();
      expect(screen.getByText('Packet Loss')).toBeInTheDocument();
    });

    it('renders preview section', () => {
      render(<LinkConfigPanel {...defaultProps} />);
      
      expect(screen.getByText('Preview:')).toBeInTheDocument();
    });

    it('renders action buttons', () => {
      render(<LinkConfigPanel {...defaultProps} />);
      
      expect(screen.getByText('Delete Link')).toBeInTheDocument();
      expect(screen.getByText('Apply Changes')).toBeInTheDocument();
    });

    it('renders close button', () => {
      render(<LinkConfigPanel {...defaultProps} />);
      
      const closeButton = screen.getByTitle('Close');
      expect(closeButton).toBeInTheDocument();
    });
  });

  // ---------------------------------------------------------------------------
  // Policy Parsing Tests
  // ---------------------------------------------------------------------------

  describe('Policy Parsing', () => {
    it('parses bandwidth in Mbps correctly', () => {
      const policy: TrafficPolicy = { ...mockPolicy, bandwidth: '100Mbps' };
      render(<LinkConfigPanel {...defaultProps} policy={policy} />);
      
      // The slider should show 100 Mbps
      expect(screen.getByText(/100\.0 Mbps/)).toBeInTheDocument();
    });

    it('parses bandwidth in Gbps correctly', () => {
      const policy: TrafficPolicy = { ...mockPolicy, bandwidth: '1Gbps' };
      render(<LinkConfigPanel {...defaultProps} policy={policy} />);
      
      // Should display as 1000 Mbps internally, formatted as 1.0 Gbps
      // There might be multiple instances (slider value and bounds)
      const gbpsElements = screen.getAllByText('1.0 Gbps');
      expect(gbpsElements.length).toBeGreaterThan(0);
    });

    it('parses latency correctly', () => {
      const policy: TrafficPolicy = { ...mockPolicy, latency: '50ms' };
      render(<LinkConfigPanel {...defaultProps} policy={policy} />);
      
      expect(screen.getByText('50 ms')).toBeInTheDocument();
    });

    it('parses jitter correctly', () => {
      const policy: TrafficPolicy = { ...mockPolicy, jitter: '10ms' };
      render(<LinkConfigPanel {...defaultProps} policy={policy} />);
      
      expect(screen.getByText('10 ms')).toBeInTheDocument();
    });

    it('parses packet loss correctly', () => {
      const policy: TrafficPolicy = { ...mockPolicy, packetLoss: '2.5%' };
      render(<LinkConfigPanel {...defaultProps} policy={policy} />);
      
      expect(screen.getByText('2.5%')).toBeInTheDocument();
    });

    it('handles null policy with default values', () => {
      render(<LinkConfigPanel {...defaultProps} policy={null} />);
      
      // Default bandwidth is 10 Mbps
      expect(screen.getByText('10.0 Mbps')).toBeInTheDocument();
    });
  });

  // ---------------------------------------------------------------------------
  // Interaction Tests
  // ---------------------------------------------------------------------------

  describe('Interactions', () => {
    it('calls onClose when close button is clicked', () => {
      render(<LinkConfigPanel {...defaultProps} />);
      
      const closeButton = screen.getByTitle('Close');
      fireEvent.click(closeButton);
      
      expect(defaultProps.onClose).toHaveBeenCalledTimes(1);
    });

    it('calls onDelete when Delete Link button is clicked', () => {
      render(<LinkConfigPanel {...defaultProps} />);
      
      const deleteButton = screen.getByText('Delete Link');
      fireEvent.click(deleteButton);
      
      expect(defaultProps.onDelete).toHaveBeenCalledWith('edge-node-1-node-2');
    });

    it('disables Apply Changes button when no changes', () => {
      render(<LinkConfigPanel {...defaultProps} />);
      
      const applyButton = screen.getByText('Apply Changes');
      expect(applyButton).toBeDisabled();
    });

    it('enables Apply Changes button after slider change', () => {
      render(<LinkConfigPanel {...defaultProps} />);
      
      // Find all range inputs (sliders)
      const sliders = screen.getAllByRole('slider');
      
      // Change the first slider (bandwidth)
      fireEvent.change(sliders[0], { target: { value: '200' } });
      
      const applyButton = screen.getByText('Apply Changes');
      expect(applyButton).not.toBeDisabled();
    });

    it('calls onPolicyChange with formatted policy when Apply Changes is clicked', () => {
      render(<LinkConfigPanel {...defaultProps} />);
      
      const sliders = screen.getAllByRole('slider');
      fireEvent.change(sliders[0], { target: { value: '200' } });
      
      const applyButton = screen.getByText('Apply Changes');
      fireEvent.click(applyButton);
      
      expect(defaultProps.onPolicyChange).toHaveBeenCalledWith(
        'edge-node-1-node-2',
        expect.objectContaining({
          bandwidth: '200.0Mbps',
        })
      );
    });

    it('shows unsaved changes notice after modification', () => {
      render(<LinkConfigPanel {...defaultProps} />);
      
      const sliders = screen.getAllByRole('slider');
      fireEvent.change(sliders[0], { target: { value: '200' } });
      
      expect(screen.getByText('You have unsaved changes')).toBeInTheDocument();
    });

    it('hides unsaved changes notice after applying', () => {
      render(<LinkConfigPanel {...defaultProps} />);
      
      const sliders = screen.getAllByRole('slider');
      fireEvent.change(sliders[0], { target: { value: '200' } });
      
      const applyButton = screen.getByText('Apply Changes');
      fireEvent.click(applyButton);
      
      expect(screen.queryByText('You have unsaved changes')).not.toBeInTheDocument();
    });
  });

  // ---------------------------------------------------------------------------
  // Slider Value Tests
  // ---------------------------------------------------------------------------

  describe('Slider Values', () => {
    it('formats bandwidth values correctly', () => {
      render(<LinkConfigPanel {...defaultProps} />);
      
      // Check the bandwidth slider displays the value
      expect(screen.getByText('50.0 Mbps')).toBeInTheDocument();
    });

    it('formats latency values correctly', () => {
      render(<LinkConfigPanel {...defaultProps} />);
      
      expect(screen.getByText('20 ms')).toBeInTheDocument();
    });

    it('formats jitter values correctly', () => {
      render(<LinkConfigPanel {...defaultProps} />);
      
      expect(screen.getByText('5 ms')).toBeInTheDocument();
    });

    it('formats packet loss values correctly', () => {
      render(<LinkConfigPanel {...defaultProps} />);
      
      expect(screen.getByText('0.5%')).toBeInTheDocument();
    });
  });

  // ---------------------------------------------------------------------------
  // Edge Cases
  // ---------------------------------------------------------------------------

  describe('Edge Cases', () => {
    it('handles missing optional callbacks gracefully', () => {
      render(
        <LinkConfigPanel
          linkId="test-link"
          sourceName="node-a"
          targetName="node-b"
          policy={mockPolicy}
        />
      );
      
      // Should render without errors even without callbacks
      expect(screen.getByText('Link Configuration')).toBeInTheDocument();
    });

    it('handles very large bandwidth values', () => {
      const policy: TrafficPolicy = { ...mockPolicy, bandwidth: '10Gbps' };
      render(<LinkConfigPanel {...defaultProps} policy={policy} />);
      
      // Should format as Gbps when >= 1000 Mbps
      expect(screen.getByText('10.0 Gbps')).toBeInTheDocument();
    });

    it('handles zero latency and jitter', () => {
      const policy: TrafficPolicy = { ...mockPolicy, latency: '0ms', jitter: '0ms' };
      render(<LinkConfigPanel {...defaultProps} policy={policy} />);
      
      // Both should show 0 ms
      const zeroMsElements = screen.getAllByText('0 ms');
      expect(zeroMsElements.length).toBeGreaterThanOrEqual(2);
    });
  });
});
