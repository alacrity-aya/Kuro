import { memo, useCallback, useState } from 'react';
import type { NodeRole } from '../../types/api';

// ============================================================================
// Types
// ============================================================================

export interface DraggableNodeItemProps {
  type: NodeRole;
  label: string;
  icon: string;
  description?: string;
  color?: string;
  collapsed?: boolean;
  onDragStart?: () => void;
  onDragEnd?: () => void;
}

// ============================================================================
// Component
// ============================================================================

function DraggableNodeItem({
  type,
  label,
  icon,
  description,
  color = '#6b7280',
  collapsed = false,
  onDragStart,
  onDragEnd,
}: DraggableNodeItemProps) {
  const [isDragging, setIsDragging] = useState(false);

  const handleDragStart = useCallback(
    (e: React.DragEvent<HTMLDivElement>) => {
      e.dataTransfer.setData('application/reactflow', JSON.stringify({
        type,
        label,
        icon,
        color,
      }));
      e.dataTransfer.effectAllowed = 'move';
      setIsDragging(true);
      onDragStart?.();
    },
    [type, label, icon, color, onDragStart]
  );

  const handleDragEnd = useCallback(() => {
    setIsDragging(false);
    onDragEnd?.();
  }, [onDragEnd]);

  return (
    <div
      className={`draggable-node-item ${isDragging ? 'dragging' : ''} ${collapsed ? 'collapsed' : ''}`}
      draggable
      onDragStart={handleDragStart}
      onDragEnd={handleDragEnd}
      title={collapsed ? label : description}
    >
      <div
        className="node-icon"
        style={{ backgroundColor: `${color}20`, border: `1px solid ${color}40` }}
      >
        {icon}
      </div>
      {!collapsed && (
        <div className="node-info">
          <span className="node-label">{label}</span>
          {description && <span className="node-description">{description}</span>}
        </div>
      )}
    </div>
  );
}

export default memo(DraggableNodeItem);
