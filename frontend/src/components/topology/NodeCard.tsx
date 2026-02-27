import { memo } from 'react';
import { Handle, Position, type NodeProps } from 'reactflow';
import type { TopologyNode, NodeRole } from '../../types/api';
import './NodeCard.css';

// ============================================================================
// Types
// ============================================================================

interface NodeCardData {
  node: TopologyNode;
  isSelected: boolean;
}

// ============================================================================
// Constants
// ============================================================================

const ROLE_CONFIG: Record<NodeRole, { icon: string; color: string; bgColor: string }> = {
  drone: { icon: '🚁', color: '#3b82f6', bgColor: '#eff6ff' },
  'ground-station': { icon: '📡', color: '#10b981', bgColor: '#ecfdf5' },
  gateway: { icon: '🔀', color: '#8b5cf6', bgColor: '#f5f3ff' },
  server: { icon: '🖥️', color: '#6366f1', bgColor: '#eef2ff' },
  client: { icon: '💻', color: '#f59e0b', bgColor: '#fffbeb' },
  custom: { icon: '📦', color: '#6b7280', bgColor: '#f9fafb' },
};

const STATUS_CONFIG: Record<TopologyNode['status'], { color: string; label: string }> = {
  running: { color: '#10b981', label: 'Running' },
  pending: { color: '#f59e0b', label: 'Pending' },
  failed: { color: '#ef4444', label: 'Failed' },
  unknown: { color: '#6b7280', label: 'Unknown' },
};

// ============================================================================
// Component
// ============================================================================

function NodeCard({ data }: NodeProps<NodeCardData>) {
  const { node, isSelected } = data;
  const roleConfig = ROLE_CONFIG[node.role] || ROLE_CONFIG.custom;
  const statusConfig = STATUS_CONFIG[node.status];

  return (
    <div
      className={`node-card ${isSelected ? 'node-card--selected' : ''}`}
      style={{
        borderColor: isSelected ? roleConfig.color : undefined,
        boxShadow: isSelected ? `0 0 0 2px ${roleConfig.color}20` : undefined,
      }}
    >
      {/* Input Handle (Left) */}
      <Handle
        type="target"
        position={Position.Left}
        className="node-card__handle"
      />

      {/* Node Content */}
      <div className="node-card__header" style={{ backgroundColor: roleConfig.bgColor }}>
        <span className="node-card__icon">{roleConfig.icon}</span>
        <div className="node-card__title-row">
          <span className="node-card__name">{node.name}</span>
          <span className="node-card__group">{node.groupId}</span>
        </div>
      </div>

      <div className="node-card__body">
        <div className="node-card__info">
          <span className="node-card__label">IP:</span>
          <span className="node-card__value">{node.ip}</span>
        </div>
        <div className="node-card__info">
          <span className="node-card__label">Role:</span>
          <span className="node-card__value">{node.role}</span>
        </div>
      </div>

      {/* Status Indicator */}
      <div className="node-card__footer">
        <div className="node-card__status">
          <span
            className="node-card__status-dot"
            style={{ backgroundColor: statusConfig.color }}
          />
          <span className="node-card__status-label">{statusConfig.label}</span>
        </div>
      </div>

      {/* Output Handle (Right) */}
      <Handle
        type="source"
        position={Position.Right}
        className="node-card__handle"
      />
    </div>
  );
}

export default memo(NodeCard);
