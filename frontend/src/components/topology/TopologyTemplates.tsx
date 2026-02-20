/**
 * TopologyTemplates - Topology Template Selector
 * 
 * Provides predefined topology templates, supports quick creation of common topology structures
 */
import { memo, useState } from 'react';
import type { NodeRole, TrafficPolicy } from '../../types/api';
import './TopologyTemplates.css';

// ============================================================================
// Types
// ============================================================================

export interface TemplateNode {
  id: string;
  name: string;
  role: NodeRole;
  x: number;
  y: number;
  labels?: Record<string, string>;
}

export interface TemplateEdge {
  id: string;
  source: string;
  target: string;
  policy?: TrafficPolicy;
}

export interface TopologyTemplate {
  id: string;
  name: string;
  description: string;
  category: 'drone' | 'iot' | 'microservice' | 'custom';
  icon: string;
  nodes: TemplateNode[];
  edges: TemplateEdge[];
}

export interface TopologyTemplatesProps {
  onSelectTemplate: (template: TopologyTemplate) => void;
  onClose?: () => void;
}

// ============================================================================
// Predefined Templates
// ============================================================================

const TEMPLATES: TopologyTemplate[] = [
  {
    id: 'drone-swarm',
    name: 'Drone Swarm',
    description: 'Drone swarm network topology - 1 ground station controlling multiple drones',
    category: 'drone',
    icon: '🚁',
    nodes: [
      { id: 'gs-1', name: 'ground-station-1', role: 'ground-station', x: 400, y: 100, labels: { role: 'ground-station' } },
      { id: 'drone-1', name: 'drone-1', role: 'drone', x: 200, y: 250, labels: { role: 'drone' } },
      { id: 'drone-2', name: 'drone-2', role: 'drone', x: 400, y: 250, labels: { role: 'drone' } },
      { id: 'drone-3', name: 'drone-3', role: 'drone', x: 600, y: 250, labels: { role: 'drone' } },
      { id: 'drone-4', name: 'drone-4', role: 'drone', x: 300, y: 400, labels: { role: 'drone' } },
      { id: 'drone-5', name: 'drone-5', role: 'drone', x: 500, y: 400, labels: { role: 'drone' } },
    ],
    edges: [
      { id: 'e-gs-d1', source: 'gs-1', target: 'drone-1', policy: { bandwidth: '10Mbps', latency: '20ms', jitter: '5ms', packetLoss: '0.1%' } },
      { id: 'e-gs-d2', source: 'gs-1', target: 'drone-2', policy: { bandwidth: '10Mbps', latency: '20ms', jitter: '5ms', packetLoss: '0.1%' } },
      { id: 'e-gs-d3', source: 'gs-1', target: 'drone-3', policy: { bandwidth: '10Mbps', latency: '20ms', jitter: '5ms', packetLoss: '0.1%' } },
      { id: 'e-gs-d4', source: 'gs-1', target: 'drone-4', policy: { bandwidth: '10Mbps', latency: '25ms', jitter: '8ms', packetLoss: '0.2%' } },
      { id: 'e-gs-d5', source: 'gs-1', target: 'drone-5', policy: { bandwidth: '10Mbps', latency: '25ms', jitter: '8ms', packetLoss: '0.2%' } },
      { id: 'e-d1-d4', source: 'drone-1', target: 'drone-4', policy: { bandwidth: '5Mbps', latency: '10ms', jitter: '2ms', packetLoss: '0.05%' } },
      { id: 'e-d2-d5', source: 'drone-2', target: 'drone-5', policy: { bandwidth: '5Mbps', latency: '10ms', jitter: '2ms', packetLoss: '0.05%' } },
    ],
  },
  {
    id: 'iot-gateway',
    name: 'IoT Gateway',
    description: 'IoT gateway topology - multiple sensors connecting to server through gateway',
    category: 'iot',
    icon: '📡',
    nodes: [
      { id: 'server-1', name: 'server-1', role: 'server', x: 400, y: 80, labels: { role: 'server' } },
      { id: 'gateway-1', name: 'gateway-1', role: 'gateway', x: 250, y: 220, labels: { role: 'gateway' } },
      { id: 'gateway-2', name: 'gateway-2', role: 'gateway', x: 550, y: 220, labels: { role: 'gateway' } },
      { id: 'client-1', name: 'sensor-1', role: 'client', x: 150, y: 380, labels: { role: 'sensor', type: 'temperature' } },
      { id: 'client-2', name: 'sensor-2', role: 'client', x: 250, y: 380, labels: { role: 'sensor', type: 'humidity' } },
      { id: 'client-3', name: 'sensor-3', role: 'client', x: 350, y: 380, labels: { role: 'sensor', type: 'pressure' } },
      { id: 'client-4', name: 'sensor-4', role: 'client', x: 450, y: 380, labels: { role: 'sensor', type: 'temperature' } },
      { id: 'client-5', name: 'sensor-5', role: 'client', x: 550, y: 380, labels: { role: 'sensor', type: 'humidity' } },
      { id: 'client-6', name: 'sensor-6', role: 'client', x: 650, y: 380, labels: { role: 'sensor', type: 'pressure' } },
    ],
    edges: [
      { id: 'e-s-g1', source: 'server-1', target: 'gateway-1', policy: { bandwidth: '100Mbps', latency: '5ms', jitter: '1ms', packetLoss: '0.01%' } },
      { id: 'e-s-g2', source: 'server-1', target: 'gateway-2', policy: { bandwidth: '100Mbps', latency: '5ms', jitter: '1ms', packetLoss: '0.01%' } },
      { id: 'e-g1-c1', source: 'gateway-1', target: 'client-1', policy: { bandwidth: '1Mbps', latency: '50ms', jitter: '20ms', packetLoss: '1%' } },
      { id: 'e-g1-c2', source: 'gateway-1', target: 'client-2', policy: { bandwidth: '1Mbps', latency: '50ms', jitter: '20ms', packetLoss: '1%' } },
      { id: 'e-g1-c3', source: 'gateway-1', target: 'client-3', policy: { bandwidth: '1Mbps', latency: '50ms', jitter: '20ms', packetLoss: '1%' } },
      { id: 'e-g2-c4', source: 'gateway-2', target: 'client-4', policy: { bandwidth: '1Mbps', latency: '50ms', jitter: '20ms', packetLoss: '1%' } },
      { id: 'e-g2-c5', source: 'gateway-2', target: 'client-5', policy: { bandwidth: '1Mbps', latency: '50ms', jitter: '20ms', packetLoss: '1%' } },
      { id: 'e-g2-c6', source: 'gateway-2', target: 'client-6', policy: { bandwidth: '1Mbps', latency: '50ms', jitter: '20ms', packetLoss: '1%' } },
    ],
  },
  {
    id: 'microservice',
    name: 'Microservices',
    description: 'Microservices architecture topology - API gateway, service cluster, database',
    category: 'microservice',
    icon: '🔗',
    nodes: [
      { id: 'gateway-1', name: 'api-gateway', role: 'gateway', x: 400, y: 80, labels: { role: 'gateway', tier: 'frontend' } },
      { id: 'server-1', name: 'user-service', role: 'server', x: 200, y: 220, labels: { role: 'server', tier: 'backend' } },
      { id: 'server-2', name: 'order-service', role: 'server', x: 400, y: 220, labels: { role: 'server', tier: 'backend' } },
      { id: 'server-3', name: 'product-service', role: 'server', x: 600, y: 220, labels: { role: 'server', tier: 'backend' } },
      { id: 'server-4', name: 'user-db', role: 'server', x: 200, y: 380, labels: { role: 'database', tier: 'data' } },
      { id: 'server-5', name: 'order-db', role: 'server', x: 400, y: 380, labels: { role: 'database', tier: 'data' } },
      { id: 'server-6', name: 'product-db', role: 'server', x: 600, y: 380, labels: { role: 'database', tier: 'data' } },
    ],
    edges: [
      { id: 'e-gw-s1', source: 'gateway-1', target: 'server-1', policy: { bandwidth: '1Gbps', latency: '2ms', jitter: '0.5ms', packetLoss: '0.001%' } },
      { id: 'e-gw-s2', source: 'gateway-1', target: 'server-2', policy: { bandwidth: '1Gbps', latency: '2ms', jitter: '0.5ms', packetLoss: '0.001%' } },
      { id: 'e-gw-s3', source: 'gateway-1', target: 'server-3', policy: { bandwidth: '1Gbps', latency: '2ms', jitter: '0.5ms', packetLoss: '0.001%' } },
      { id: 'e-s1-db1', source: 'server-1', target: 'server-4', policy: { bandwidth: '500Mbps', latency: '1ms', jitter: '0.1ms', packetLoss: '0%' } },
      { id: 'e-s2-db2', source: 'server-2', target: 'server-5', policy: { bandwidth: '500Mbps', latency: '1ms', jitter: '0.1ms', packetLoss: '0%' } },
      { id: 'e-s3-db3', source: 'server-3', target: 'server-6', policy: { bandwidth: '500Mbps', latency: '1ms', jitter: '0.1ms', packetLoss: '0%' } },
      { id: 'e-s1-s2', source: 'server-1', target: 'server-2', policy: { bandwidth: '200Mbps', latency: '1ms', jitter: '0.2ms', packetLoss: '0%' } },
      { id: 'e-s2-s3', source: 'server-2', target: 'server-3', policy: { bandwidth: '200Mbps', latency: '1ms', jitter: '0.2ms', packetLoss: '0%' } },
    ],
  },
  {
    id: 'star-topology',
    name: 'Star Topology',
    description: 'Star topology - central node connecting multiple edge nodes',
    category: 'custom',
    icon: '⭐',
    nodes: [
      { id: 'server-1', name: 'central-hub', role: 'server', x: 400, y: 250, labels: { role: 'hub' } },
      { id: 'client-1', name: 'edge-1', role: 'client', x: 400, y: 80, labels: { role: 'edge' } },
      { id: 'client-2', name: 'edge-2', role: 'client', x: 600, y: 150, labels: { role: 'edge' } },
      { id: 'client-3', name: 'edge-3', role: 'client', x: 600, y: 350, labels: { role: 'edge' } },
      { id: 'client-4', name: 'edge-4', role: 'client', x: 400, y: 420, labels: { role: 'edge' } },
      { id: 'client-5', name: 'edge-5', role: 'client', x: 200, y: 350, labels: { role: 'edge' } },
      { id: 'client-6', name: 'edge-6', role: 'client', x: 200, y: 150, labels: { role: 'edge' } },
    ],
    edges: [
      { id: 'e-h-e1', source: 'server-1', target: 'client-1', policy: { bandwidth: '50Mbps', latency: '10ms', jitter: '2ms', packetLoss: '0.1%' } },
      { id: 'e-h-e2', source: 'server-1', target: 'client-2', policy: { bandwidth: '50Mbps', latency: '10ms', jitter: '2ms', packetLoss: '0.1%' } },
      { id: 'e-h-e3', source: 'server-1', target: 'client-3', policy: { bandwidth: '50Mbps', latency: '10ms', jitter: '2ms', packetLoss: '0.1%' } },
      { id: 'e-h-e4', source: 'server-1', target: 'client-4', policy: { bandwidth: '50Mbps', latency: '10ms', jitter: '2ms', packetLoss: '0.1%' } },
      { id: 'e-h-e5', source: 'server-1', target: 'client-5', policy: { bandwidth: '50Mbps', latency: '10ms', jitter: '2ms', packetLoss: '0.1%' } },
      { id: 'e-h-e6', source: 'server-1', target: 'client-6', policy: { bandwidth: '50Mbps', latency: '10ms', jitter: '2ms', packetLoss: '0.1%' } },
    ],
  },
  {
    id: 'mesh-topology',
    name: 'Mesh Network',
    description: 'Mesh topology - all nodes interconnected',
    category: 'custom',
    icon: '🌐',
    nodes: [
      { id: 'gateway-1', name: 'node-1', role: 'gateway', x: 300, y: 100, labels: { role: 'router' } },
      { id: 'gateway-2', name: 'node-2', role: 'gateway', x: 500, y: 100, labels: { role: 'router' } },
      { id: 'gateway-3', name: 'node-3', role: 'gateway', x: 200, y: 280, labels: { role: 'router' } },
      { id: 'gateway-4', name: 'node-4', role: 'gateway', x: 400, y: 280, labels: { role: 'router' } },
      { id: 'gateway-5', name: 'node-5', role: 'gateway', x: 600, y: 280, labels: { role: 'router' } },
      { id: 'gateway-6', name: 'node-6', role: 'gateway', x: 300, y: 460, labels: { role: 'router' } },
      { id: 'gateway-7', name: 'node-7', role: 'gateway', x: 500, y: 460, labels: { role: 'router' } },
    ],
    edges: [
      { id: 'e-1-2', source: 'gateway-1', target: 'gateway-2', policy: { bandwidth: '100Mbps', latency: '5ms', jitter: '1ms', packetLoss: '0.05%' } },
      { id: 'e-1-3', source: 'gateway-1', target: 'gateway-3', policy: { bandwidth: '100Mbps', latency: '5ms', jitter: '1ms', packetLoss: '0.05%' } },
      { id: 'e-1-4', source: 'gateway-1', target: 'gateway-4', policy: { bandwidth: '100Mbps', latency: '5ms', jitter: '1ms', packetLoss: '0.05%' } },
      { id: 'e-2-4', source: 'gateway-2', target: 'gateway-4', policy: { bandwidth: '100Mbps', latency: '5ms', jitter: '1ms', packetLoss: '0.05%' } },
      { id: 'e-2-5', source: 'gateway-2', target: 'gateway-5', policy: { bandwidth: '100Mbps', latency: '5ms', jitter: '1ms', packetLoss: '0.05%' } },
      { id: 'e-3-4', source: 'gateway-3', target: 'gateway-4', policy: { bandwidth: '100Mbps', latency: '5ms', jitter: '1ms', packetLoss: '0.05%' } },
      { id: 'e-3-6', source: 'gateway-3', target: 'gateway-6', policy: { bandwidth: '100Mbps', latency: '5ms', jitter: '1ms', packetLoss: '0.05%' } },
      { id: 'e-4-5', source: 'gateway-4', target: 'gateway-5', policy: { bandwidth: '100Mbps', latency: '5ms', jitter: '1ms', packetLoss: '0.05%' } },
      { id: 'e-4-6', source: 'gateway-4', target: 'gateway-6', policy: { bandwidth: '100Mbps', latency: '5ms', jitter: '1ms', packetLoss: '0.05%' } },
      { id: 'e-4-7', source: 'gateway-4', target: 'gateway-7', policy: { bandwidth: '100Mbps', latency: '5ms', jitter: '1ms', packetLoss: '0.05%' } },
      { id: 'e-5-7', source: 'gateway-5', target: 'gateway-7', policy: { bandwidth: '100Mbps', latency: '5ms', jitter: '1ms', packetLoss: '0.05%' } },
      { id: 'e-6-7', source: 'gateway-6', target: 'gateway-7', policy: { bandwidth: '100Mbps', latency: '5ms', jitter: '1ms', packetLoss: '0.05%' } },
    ],
  },
  {
    id: 'tree-topology',
    name: 'Tree Topology',
    description: 'Tree topology - hierarchical network structure',
    category: 'custom',
    icon: '🌲',
    nodes: [
      { id: 'server-1', name: 'root', role: 'server', x: 400, y: 60, labels: { role: 'root', level: '0' } },
      { id: 'gateway-1', name: 'branch-1', role: 'gateway', x: 250, y: 180, labels: { role: 'branch', level: '1' } },
      { id: 'gateway-2', name: 'branch-2', role: 'gateway', x: 550, y: 180, labels: { role: 'branch', level: '1' } },
      { id: 'client-1', name: 'leaf-1', role: 'client', x: 150, y: 320, labels: { role: 'leaf', level: '2' } },
      { id: 'client-2', name: 'leaf-2', role: 'client', x: 250, y: 320, labels: { role: 'leaf', level: '2' } },
      { id: 'client-3', name: 'leaf-3', role: 'client', x: 350, y: 320, labels: { role: 'leaf', level: '2' } },
      { id: 'client-4', name: 'leaf-4', role: 'client', x: 450, y: 320, labels: { role: 'leaf', level: '2' } },
      { id: 'client-5', name: 'leaf-5', role: 'client', x: 550, y: 320, labels: { role: 'leaf', level: '2' } },
      { id: 'client-6', name: 'leaf-6', role: 'client', x: 650, y: 320, labels: { role: 'leaf', level: '2' } },
    ],
    edges: [
      { id: 'e-r-b1', source: 'server-1', target: 'gateway-1', policy: { bandwidth: '200Mbps', latency: '5ms', jitter: '1ms', packetLoss: '0.01%' } },
      { id: 'e-r-b2', source: 'server-1', target: 'gateway-2', policy: { bandwidth: '200Mbps', latency: '5ms', jitter: '1ms', packetLoss: '0.01%' } },
      { id: 'e-b1-l1', source: 'gateway-1', target: 'client-1', policy: { bandwidth: '50Mbps', latency: '10ms', jitter: '3ms', packetLoss: '0.1%' } },
      { id: 'e-b1-l2', source: 'gateway-1', target: 'client-2', policy: { bandwidth: '50Mbps', latency: '10ms', jitter: '3ms', packetLoss: '0.1%' } },
      { id: 'e-b1-l3', source: 'gateway-1', target: 'client-3', policy: { bandwidth: '50Mbps', latency: '10ms', jitter: '3ms', packetLoss: '0.1%' } },
      { id: 'e-b2-l4', source: 'gateway-2', target: 'client-4', policy: { bandwidth: '50Mbps', latency: '10ms', jitter: '3ms', packetLoss: '0.1%' } },
      { id: 'e-b2-l5', source: 'gateway-2', target: 'client-5', policy: { bandwidth: '50Mbps', latency: '10ms', jitter: '3ms', packetLoss: '0.1%' } },
      { id: 'e-b2-l6', source: 'gateway-2', target: 'client-6', policy: { bandwidth: '50Mbps', latency: '10ms', jitter: '3ms', packetLoss: '0.1%' } },
    ],
  },
];

// ============================================================================
// Component
// ============================================================================

function TopologyTemplates({ onSelectTemplate, onClose }: TopologyTemplatesProps) {
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [hoveredTemplate, setHoveredTemplate] = useState<string | null>(null);

  const categories = [
    { id: 'all', label: 'All', icon: '📋' },
    { id: 'drone', label: 'Drone', icon: '🚁' },
    { id: 'iot', label: 'IoT', icon: '📡' },
    { id: 'microservice', label: 'Microservice', icon: '🔗' },
    { id: 'custom', label: 'Custom', icon: '⚙️' },
  ];

  const filteredTemplates = selectedCategory === 'all'
    ? TEMPLATES
    : TEMPLATES.filter((t) => t.category === selectedCategory);

  return (
    <div className="topology-templates">
      <div className="templates-header">
        <h3>Topology Templates</h3>
        <p className="templates-subtitle">Choose a template to quickly create a topology</p>
        {onClose && (
          <button className="templates-close-btn" onClick={onClose} aria-label="Close">
            ✕
          </button>
        )}
      </div>

      <div className="templates-categories">
        {categories.map((cat) => (
          <button
            key={cat.id}
            className={`category-btn ${selectedCategory === cat.id ? 'active' : ''}`}
            onClick={() => setSelectedCategory(cat.id)}
          >
            <span className="category-icon">{cat.icon}</span>
            <span className="category-label">{cat.label}</span>
          </button>
        ))}
      </div>

      <div className="templates-grid">
        {filteredTemplates.map((template) => (
          <div
            key={template.id}
            className={`template-card ${hoveredTemplate === template.id ? 'hovered' : ''}`}
            onMouseEnter={() => setHoveredTemplate(template.id)}
            onMouseLeave={() => setHoveredTemplate(null)}
            onClick={() => onSelectTemplate(template)}
          >
            <div className="template-icon">{template.icon}</div>
            <div className="template-info">
              <h4 className="template-name">{template.name}</h4>
              <p className="template-description">{template.description}</p>
              <div className="template-stats">
                <span className="stat">
                  <span className="stat-icon">●</span>
                  {template.nodes.length} nodes
                </span>
                <span className="stat">
                  <span className="stat-icon">―</span>
                  {template.edges.length} links
                </span>
              </div>
            </div>
            {hoveredTemplate === template.id && (
              <div className="template-overlay">
                <span className="use-template-text">Click to use template</span>
              </div>
            )}
          </div>
        ))}
      </div>

      {filteredTemplates.length === 0 && (
        <div className="templates-empty">
          <span className="empty-icon">📭</span>
          <p>No templates found in this category</p>
        </div>
      )}
    </div>
  );
}

export { TEMPLATES };
export default memo(TopologyTemplates);
