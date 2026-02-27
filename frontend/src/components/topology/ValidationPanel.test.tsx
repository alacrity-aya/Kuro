import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { createMemoryRouter, RouterProvider } from 'react-router-dom';
import ValidationPanel, { ValidationQuickStats } from './ValidationPanel';
import type { ValidationResult, ValidationIssue } from '../../utils/topologyValidator';

// Helper to create a mock validation result
function createMockValidationResult(overrides: Partial<ValidationResult> = {}): ValidationResult {
  return {
    isValid: true,
    hasErrors: false,
    hasWarnings: false,
    issues: [],
    summary: {
      totalNodes: 0,
      totalEdges: 0,
      connectedNodes: 0,
      isolatedNodes: 0,
      duplicateNames: [],
    },
    ...overrides,
  };
}

// Helper to wrap component with router
function renderWithRouter(component: React.ReactNode) {
  const router = createMemoryRouter([
    {
      path: '/',
      element: component,
    },
  ]);
  return render(<RouterProvider router={router} />);
}

describe('ValidationPanel', () => {
  describe('rendering', () => {
    it('renders valid state with no issues', () => {
      const result = createMockValidationResult();
      renderWithRouter(<ValidationPanel validationResult={result} />);
      
      expect(screen.getByText('Validation')).toBeInTheDocument();
      expect(screen.getByText('No issues found')).toBeInTheDocument();
      expect(screen.getByText('🎉')).toBeInTheDocument();
    });

    it('renders errors correctly', () => {
      const result = createMockValidationResult({
        isValid: false,
        hasErrors: true,
        issues: [
          {
            id: 'error-1',
            type: 'error',
            message: 'Node name is required',
            nodeId: 'node-1',
          },
        ],
      });
      
      renderWithRouter(<ValidationPanel validationResult={result} />);
      
      expect(screen.getByText('Node name is required')).toBeInTheDocument();
      // Multiple error icons, check for the title icon
      expect(screen.getAllByText('❌').length).toBeGreaterThan(0);
    });

    it('renders warnings correctly', () => {
      const result = createMockValidationResult({
        hasWarnings: true,
        issues: [
          {
            id: 'warning-1',
            type: 'warning',
            message: 'Node "test" has no connections',
            nodeId: 'node-1',
          },
        ],
      });
      
      renderWithRouter(<ValidationPanel validationResult={result} />);
      
      expect(screen.getByText('Node "test" has no connections')).toBeInTheDocument();
      // Multiple warning icons, check for presence
      expect(screen.getAllByText('⚠️').length).toBeGreaterThan(0);
    });

    it('renders info messages correctly', () => {
      const result = createMockValidationResult({
        issues: [
          {
            id: 'info-1',
            type: 'info',
            message: 'This is an info message',
          },
        ],
      });
      
      renderWithRouter(<ValidationPanel validationResult={result} />);
      
      expect(screen.getByText('This is an info message')).toBeInTheDocument();
    });

    it('renders suggestions when provided', () => {
      const result = createMockValidationResult({
        hasWarnings: true,
        issues: [
          {
            id: 'warning-1',
            type: 'warning',
            message: 'Invalid bandwidth format',
            suggestion: 'Use format like "10Mbps"',
          },
        ],
      });
      
      renderWithRouter(<ValidationPanel validationResult={result} />);
      
      expect(screen.getByText(/Use format like "10Mbps"/)).toBeInTheDocument();
    });

    it('renders node location when nodeId is provided', () => {
      const result = createMockValidationResult({
        hasWarnings: true,
        issues: [
          {
            id: 'warning-1',
            type: 'warning',
            message: 'Issue with node',
            nodeId: 'node-123',
          },
        ],
      });
      
      renderWithRouter(<ValidationPanel validationResult={result} />);
      
      expect(screen.getByText(/Node: node-123/)).toBeInTheDocument();
    });

    it('renders edge location when edgeId is provided', () => {
      const result = createMockValidationResult({
        hasWarnings: true,
        issues: [
          {
            id: 'warning-1',
            type: 'warning',
            message: 'Issue with edge',
            edgeId: 'edge-456',
          },
        ],
      });
      
      renderWithRouter(<ValidationPanel validationResult={result} />);
      
      expect(screen.getByText(/Link: edge-456/)).toBeInTheDocument();
    });
  });

  describe('summary display', () => {
    it('displays summary with node and edge counts', () => {
      const result = createMockValidationResult({
        hasWarnings: true,
        issues: [
          {
            id: 'warning-1',
            type: 'warning',
            message: 'Some warning',
          },
        ],
        summary: {
          totalNodes: 5,
          totalEdges: 3,
          connectedNodes: 5,
          isolatedNodes: 0,
          duplicateNames: [],
        },
      });
      
      renderWithRouter(<ValidationPanel validationResult={result} showSummary={true} />);
      
      expect(screen.getByText('Nodes:')).toBeInTheDocument();
      expect(screen.getByText('5')).toBeInTheDocument();
      expect(screen.getByText('Links:')).toBeInTheDocument();
      expect(screen.getByText('3')).toBeInTheDocument();
    });

    it('displays isolated nodes count when present', () => {
      const result = createMockValidationResult({
        hasWarnings: true,
        issues: [
          {
            id: 'warning-1',
            type: 'warning',
            message: 'Node is isolated',
            nodeId: 'node-1',
          },
        ],
        summary: {
          totalNodes: 5,
          totalEdges: 3,
          connectedNodes: 4,
          isolatedNodes: 1,
          duplicateNames: [],
        },
      });
      
      renderWithRouter(<ValidationPanel validationResult={result} showSummary={true} />);
      
      expect(screen.getByText('Isolated:')).toBeInTheDocument();
      // Use getAllByText since there are multiple '1's
      const ones = screen.getAllByText('1');
      expect(ones.length).toBeGreaterThan(0);
    });
  });

  describe('interactions', () => {
    it('calls onIssueClick when issue is clicked', () => {
      const issue: ValidationIssue = {
        id: 'error-1',
        type: 'error',
        message: 'Test error',
        nodeId: 'node-1',
      };
      
      const result = createMockValidationResult({
        hasErrors: true,
        issues: [issue],
      });
      
      const handleClick = vi.fn();
      renderWithRouter(<ValidationPanel validationResult={result} onIssueClick={handleClick} />);
      
      fireEvent.click(screen.getByText('Test error'));
      
      expect(handleClick).toHaveBeenCalledWith(issue);
    });

    it('calls onToggle when toggle button is clicked', () => {
      const result = createMockValidationResult({
        hasWarnings: true,
        issues: [
          {
            id: 'warning-1',
            type: 'warning',
            message: 'Test warning',
          },
        ],
      });
      
      const handleToggle = vi.fn();
      renderWithRouter(<ValidationPanel validationResult={result} onToggle={handleToggle} />);
      
      // Find the toggle button by its aria-label
      const toggleButton = screen.getByLabelText(/collapse/i);
      fireEvent.click(toggleButton);
      
      expect(handleToggle).toHaveBeenCalled();
    });

    it('collapses issues when collapsed prop is true', () => {
      const result = createMockValidationResult({
        hasWarnings: true,
        issues: [
          {
            id: 'warning-1',
            type: 'warning',
            message: 'Test warning',
          },
        ],
      });
      
      renderWithRouter(<ValidationPanel validationResult={result} collapsed={true} />);
      
      // Issues should not be visible when collapsed
      expect(screen.queryByText('Test warning')).not.toBeInTheDocument();
    });
  });

  describe('error count badges', () => {
    it('shows error count badge when there are errors', () => {
      const result = createMockValidationResult({
        hasErrors: true,
        issues: [
          { id: 'error-1', type: 'error', message: 'Error 1' },
          { id: 'error-2', type: 'error', message: 'Error 2' },
        ],
      });
      
      renderWithRouter(<ValidationPanel validationResult={result} />);
      
      expect(screen.getByText('2')).toBeInTheDocument();
    });

    it('shows warning count badge when there are warnings', () => {
      const result = createMockValidationResult({
        hasWarnings: true,
        issues: [
          { id: 'warning-1', type: 'warning', message: 'Warning 1' },
          { id: 'warning-2', type: 'warning', message: 'Warning 2' },
          { id: 'warning-3', type: 'warning', message: 'Warning 3' },
        ],
      });
      
      renderWithRouter(<ValidationPanel validationResult={result} />);
      
      expect(screen.getByText('3')).toBeInTheDocument();
    });
  });
});

describe('ValidationQuickStats', () => {
  it('shows valid state when no issues', () => {
    const result = createMockValidationResult();
    renderWithRouter(<ValidationQuickStats validationResult={result} />);
    
    expect(screen.getByText('Valid')).toBeInTheDocument();
    expect(screen.getByText('✅')).toBeInTheDocument();
  });

  it('shows error count when there are errors', () => {
    const result = createMockValidationResult({
      isValid: false,
      hasErrors: true,
      issues: [
        { id: 'error-1', type: 'error', message: 'Error 1' },
      ],
    });
    
    renderWithRouter(<ValidationQuickStats validationResult={result} />);
    
    expect(screen.getByText(/error/i)).toBeInTheDocument();
  });

  it('shows warning count when there are warnings', () => {
    const result = createMockValidationResult({
      hasWarnings: true,
      issues: [
        { id: 'warning-1', type: 'warning', message: 'Warning 1' },
        { id: 'warning-2', type: 'warning', message: 'Warning 2' },
      ],
    });
    
    renderWithRouter(<ValidationQuickStats validationResult={result} />);
    
    expect(screen.getByText(/warning/i)).toBeInTheDocument();
  });

  it('calls onClick when clicked', () => {
    const result = createMockValidationResult({
      hasWarnings: true,
      issues: [
        { id: 'warning-1', type: 'warning', message: 'Warning' },
      ],
    });
    
    const handleClick = vi.fn();
    renderWithRouter(<ValidationQuickStats validationResult={result} onClick={handleClick} />);
    
    // Click on the stats
    fireEvent.click(screen.getByText(/warning/i));
    
    expect(handleClick).toHaveBeenCalled();
  });
});
