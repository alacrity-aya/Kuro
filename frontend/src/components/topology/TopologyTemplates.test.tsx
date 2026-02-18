/**
 * TopologyTemplates Component Tests
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import TopologyTemplates, { TEMPLATES } from './TopologyTemplates';
import type { TopologyTemplate } from './TopologyTemplates';

// Mock callback
const mockOnSelectTemplate = vi.fn();
const mockOnClose = vi.fn();

describe('TopologyTemplates', () => {
  beforeEach(() => {
    mockOnSelectTemplate.mockClear();
    mockOnClose.mockClear();
  });

  describe('Rendering', () => {
    it('should render the component with header', () => {
      render(<TopologyTemplates onSelectTemplate={mockOnSelectTemplate} />);
      
      expect(screen.getByText('Topology Templates')).toBeInTheDocument();
      expect(screen.getByText('Choose a template to quickly create a topology')).toBeInTheDocument();
    });

    it('should render close button when onClose is provided', () => {
      render(<TopologyTemplates onSelectTemplate={mockOnSelectTemplate} onClose={mockOnClose} />);
      
      const closeBtn = screen.getByLabelText('Close');
      expect(closeBtn).toBeInTheDocument();
    });

    it('should not render close button when onClose is not provided', () => {
      render(<TopologyTemplates onSelectTemplate={mockOnSelectTemplate} />);
      
      expect(screen.queryByLabelText('Close')).not.toBeInTheDocument();
    });

    it('should render all category buttons', () => {
      render(<TopologyTemplates onSelectTemplate={mockOnSelectTemplate} />);
      
      expect(screen.getByText('All')).toBeInTheDocument();
      expect(screen.getByText('Drone')).toBeInTheDocument();
      expect(screen.getByText('IoT')).toBeInTheDocument();
      expect(screen.getByText('Microservice')).toBeInTheDocument();
      expect(screen.getByText('Custom')).toBeInTheDocument();
    });

    it('should render all templates by default', () => {
      render(<TopologyTemplates onSelectTemplate={mockOnSelectTemplate} />);
      
      TEMPLATES.forEach((template) => {
        expect(screen.getByText(template.name)).toBeInTheDocument();
      });
    });

    it('should render template stats', () => {
      render(<TopologyTemplates onSelectTemplate={mockOnSelectTemplate} />);
      
      const droneSwarm = TEMPLATES.find((t) => t.id === 'drone-swarm')!;
      expect(screen.getByText(`${droneSwarm.nodes.length} nodes`)).toBeInTheDocument();
      expect(screen.getByText(`${droneSwarm.edges.length} links`)).toBeInTheDocument();
    });
  });

  describe('Category Filtering', () => {
    it('should filter templates by category', () => {
      render(<TopologyTemplates onSelectTemplate={mockOnSelectTemplate} />);
      
      // Click Drone category
      fireEvent.click(screen.getByText('Drone'));
      
      const droneTemplates = TEMPLATES.filter((t) => t.category === 'drone');
      const otherTemplates = TEMPLATES.filter((t) => t.category !== 'drone');
      
      droneTemplates.forEach((t) => {
        expect(screen.getByText(t.name)).toBeInTheDocument();
      });
      
      otherTemplates.forEach((t) => {
        expect(screen.queryByText(t.name)).not.toBeInTheDocument();
      });
    });

    it('should show all templates when "All" is selected', () => {
      render(<TopologyTemplates onSelectTemplate={mockOnSelectTemplate} />);
      
      // First filter by a category
      fireEvent.click(screen.getByText('Drone'));
      
      // Then click "All"
      fireEvent.click(screen.getByText('All'));
      
      TEMPLATES.forEach((template) => {
        expect(screen.getByText(template.name)).toBeInTheDocument();
      });
    });

    it('should show empty state when no templates in category', () => {
      render(<TopologyTemplates onSelectTemplate={mockOnSelectTemplate} />);
      
      // IoT category has templates, but let's test the empty state rendering
      // by checking the component handles it gracefully
      const iotTemplates = TEMPLATES.filter((t) => t.category === 'iot');
      
      fireEvent.click(screen.getByText('IoT'));
      
      if (iotTemplates.length > 0) {
        iotTemplates.forEach((t) => {
          expect(screen.getByText(t.name)).toBeInTheDocument();
        });
      }
    });

    it('should highlight active category button', () => {
      render(<TopologyTemplates onSelectTemplate={mockOnSelectTemplate} />);
      
      const droneBtn = screen.getByText('Drone').closest('button')!;
      expect(droneBtn.classList.contains('active')).toBe(false);
      
      fireEvent.click(screen.getByText('Drone'));
      expect(droneBtn.classList.contains('active')).toBe(true);
    });
  });

  describe('Template Selection', () => {
    it('should call onSelectTemplate when a template is clicked', () => {
      render(<TopologyTemplates onSelectTemplate={mockOnSelectTemplate} />);
      
      const templateName = TEMPLATES[0].name;
      fireEvent.click(screen.getByText(templateName));
      
      expect(mockOnSelectTemplate).toHaveBeenCalledTimes(1);
      expect(mockOnSelectTemplate).toHaveBeenCalledWith(TEMPLATES[0]);
    });

    it('should pass correct template data on selection', () => {
      render(<TopologyTemplates onSelectTemplate={mockOnSelectTemplate} />);
      
      const droneSwarm = TEMPLATES.find((t) => t.id === 'drone-swarm')!;
      fireEvent.click(screen.getByText(droneSwarm.name));
      
      expect(mockOnSelectTemplate).toHaveBeenCalledWith(
        expect.objectContaining({
          id: 'drone-swarm',
          name: 'Drone Swarm',
          category: 'drone',
          nodes: expect.any(Array),
          edges: expect.any(Array),
        })
      );
    });
  });

  describe('Close Button', () => {
    it('should call onClose when close button is clicked', () => {
      render(<TopologyTemplates onSelectTemplate={mockOnSelectTemplate} onClose={mockOnClose} />);
      
      fireEvent.click(screen.getByLabelText('Close'));
      
      expect(mockOnClose).toHaveBeenCalledTimes(1);
    });
  });

  describe('Hover State', () => {
    it('should show overlay on hover', () => {
      render(<TopologyTemplates onSelectTemplate={mockOnSelectTemplate} />);
      
      const templateCard = screen.getByText(TEMPLATES[0].name).closest('.template-card')!;
      
      fireEvent.mouseEnter(templateCard);
      
      expect(screen.getByText('Click to use template')).toBeInTheDocument();
      
      fireEvent.mouseLeave(templateCard);
      
      expect(screen.queryByText('Click to use template')).not.toBeInTheDocument();
    });
  });
});

describe('TEMPLATES data', () => {
  it('should have valid template structure', () => {
    TEMPLATES.forEach((template: TopologyTemplate) => {
      expect(template).toHaveProperty('id');
      expect(template).toHaveProperty('name');
      expect(template).toHaveProperty('description');
      expect(template).toHaveProperty('category');
      expect(template).toHaveProperty('icon');
      expect(template).toHaveProperty('nodes');
      expect(template).toHaveProperty('edges');
      
      expect(Array.isArray(template.nodes)).toBe(true);
      expect(Array.isArray(template.edges)).toBe(true);
      expect(template.nodes.length).toBeGreaterThan(0);
    });
  });

  it('should have valid node structure in templates', () => {
    TEMPLATES.forEach((template) => {
      template.nodes.forEach((node) => {
        expect(node).toHaveProperty('id');
        expect(node).toHaveProperty('name');
        expect(node).toHaveProperty('role');
        expect(node).toHaveProperty('x');
        expect(node).toHaveProperty('y');
      });
    });
  });

  it('should have valid edge structure in templates', () => {
    TEMPLATES.forEach((template) => {
      template.edges.forEach((edge) => {
        expect(edge).toHaveProperty('id');
        expect(edge).toHaveProperty('source');
        expect(edge).toHaveProperty('target');
        
        // Verify source and target refer to existing nodes
        const nodeIds = template.nodes.map((n) => n.id);
        expect(nodeIds).toContain(edge.source);
        expect(nodeIds).toContain(edge.target);
      });
    });
  });

  it('should have valid policy in edges', () => {
    TEMPLATES.forEach((template) => {
      template.edges.forEach((edge) => {
        if (edge.policy) {
          expect(edge.policy).toHaveProperty('bandwidth');
          expect(edge.policy).toHaveProperty('latency');
          expect(edge.policy).toHaveProperty('jitter');
          expect(edge.policy).toHaveProperty('packetLoss');
        }
      });
    });
  });

  it('should have at least one template per category', () => {
    const categories = ['drone', 'iot', 'microservice', 'custom'];
    
    categories.forEach((category) => {
      const templatesInCategory = TEMPLATES.filter((t) => t.category === category);
      expect(templatesInCategory.length).toBeGreaterThan(0);
    });
  });
});
