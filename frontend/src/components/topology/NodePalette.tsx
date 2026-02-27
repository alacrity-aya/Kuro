import { memo } from 'react';
import type { NodeRole } from '../../types/api';
import DraggableNodeItem from './DraggableNodeItem';
import './NodePalette.css';

// ============================================================================
// Constants
// ============================================================================

interface NodeTypeConfig {
  type: NodeRole;
  label: string;
  icon: string;
  description: string;
  defaultImage: string;
  color: string;
}

const NODE_TYPES: NodeTypeConfig[] = [
  {
    type: 'drone',
    label: 'Drone',
    icon: '🚁',
    description: 'UAV/Drone node',
    defaultImage: 'nicolaka/netshoot',
    color: '#3b82f6',
  },
  {
    type: 'ground-station',
    label: 'Ground Station',
    icon: '📡',
    description: 'Ground control station',
    defaultImage: 'nicolaka/netshoot',
    color: '#10b981',
  },
  {
    type: 'gateway',
    label: 'Gateway',
    icon: '🌐',
    description: 'Network gateway node',
    defaultImage: 'nicolaka/netshoot',
    color: '#f59e0b',
  },
  {
    type: 'server',
    label: 'Server',
    icon: '🖥️',
    description: 'Server node',
    defaultImage: 'nginx:alpine',
    color: '#8b5cf6',
  },
  {
    type: 'client',
    label: 'Client',
    icon: '💻',
    description: 'Client node',
    defaultImage: 'busybox',
    color: '#ec4899',
  },
];

// ============================================================================
// Types
// ============================================================================

export interface NodePaletteProps {
  className?: string;
  collapsed?: boolean;
  onNodeDragStart?: (nodeType: NodeRole, config: NodeTypeConfig) => void;
}

// ============================================================================
// Component
// ============================================================================

function NodePalette({ className, collapsed = false, onNodeDragStart }: NodePaletteProps) {
  const handleDragStart = (nodeType: NodeRole, config: NodeTypeConfig) => {
    onNodeDragStart?.(nodeType, config);
  };

  return (
    <div className={`node-palette ${collapsed ? 'collapsed' : ''} ${className || ''}`}>
      <div className="palette-header">
        <h3>{collapsed ? '' : 'Node Types'}</h3>
      </div>
      <div className="palette-content">
        {NODE_TYPES.map((config) => (
          <DraggableNodeItem
            key={config.type}
            type={config.type}
            label={config.label}
            icon={config.icon}
            description={config.description}
            color={config.color}
            onDragStart={() => handleDragStart(config.type, config)}
            collapsed={collapsed}
          />
        ))}
      </div>
      {!collapsed && (
        <div className="palette-footer">
          <span className="hint">Drag nodes to canvas</span>
        </div>
      )}
    </div>
  );
}

export default memo(NodePalette);

// Export config for external use
export { NODE_TYPES };
export type { NodeTypeConfig };
