import { useState, useCallback, useMemo, memo } from 'react';
import type { NodeRole } from '../../types/api';
import './NodeGroupPanel.css';

// ============================================================================
// Types
// ============================================================================

export interface NodeGroupPanelProps {
  groups: NodeGroupInfo[];
  selectedNodeIds: string[];
  availableNodes: { id: string; name: string; role: NodeRole }[];
  onCreateGroup: (name: string, nodeIds: string[], config: GroupConfig) => void;
  onUpdateGroup: (groupId: string, config: GroupConfig) => void;
  onDeleteGroup: (groupId: string) => void;
  /** Future feature: Add nodes to existing group */
  onAddNodesToGroup?: (groupId: string, nodeIds: string[]) => void;
  onRemoveNodeFromGroup: (groupId: string, nodeId: string) => void;
  onClose?: () => void;
}

export interface NodeGroupInfo {
  id: string;
  name: string;
  role: NodeRole;
  replicas: number;
  image: string;
  labels: Record<string, string>;
  nodeIds: string[];
}

export interface GroupConfig {
  name: string;
  replicas: number;
  image: string;
  labels: Record<string, string>;
}

interface ValidationError {
  field: string;
  message: string;
}

// ============================================================================
// Constants
// ============================================================================

const ROLE_COLORS: Record<NodeRole, string> = {
  drone: '#3b82f6',
  'ground-station': '#10b981',
  gateway: '#f59e0b',
  server: '#8b5cf6',
  client: '#ec4899',
  custom: '#6b7280',
};

const ROLE_LABELS: Record<NodeRole, string> = {
  drone: 'Drone',
  'ground-station': 'Ground Station',
  gateway: 'Gateway',
  server: 'Server',
  client: 'Client',
  custom: 'Custom',
};

// ============================================================================
// Sub-Components
// ============================================================================

interface GroupCardProps {
  group: NodeGroupInfo;
  nodes: { id: string; name: string; role: NodeRole }[];
  onUpdate: (config: GroupConfig) => void;
  onDelete: () => void;
  onRemoveNode: (nodeId: string) => void;
  isExpanded: boolean;
  onToggle: () => void;
}

function GroupCard({
  group,
  nodes,
  onUpdate,
  onDelete,
  onRemoveNode,
  isExpanded,
  onToggle,
}: GroupCardProps) {
  const [editing, setEditing] = useState(false);
  const [editConfig, setEditConfig] = useState<GroupConfig>({
    name: group.name,
    replicas: group.replicas,
    image: group.image,
    labels: { ...group.labels },
  });

  const groupNodes = useMemo(
    () => nodes.filter((n) => group.nodeIds.includes(n.id)),
    [nodes, group.nodeIds]
  );

  const handleSave = useCallback(() => {
    onUpdate(editConfig);
    setEditing(false);
  }, [editConfig, onUpdate]);

  const handleCancel = useCallback(() => {
    setEditConfig({
      name: group.name,
      replicas: group.replicas,
      image: group.image,
      labels: { ...group.labels },
    });
    setEditing(false);
  }, [group]);

  return (
    <div className="ngp-group-card">
      <div className="ngp-group-header" onClick={onToggle}>
        <div
          className="ngp-group-color"
          style={{ backgroundColor: ROLE_COLORS[group.role] }}
        />
        <div className="ngp-group-info">
          <span className="ngp-group-name">{group.name}</span>
          <span className="ngp-group-meta">
            {group.replicas} nodes · {ROLE_LABELS[group.role]}
          </span>
        </div>
        <div className="ngp-group-actions">
          <span className="ngp-expand-icon">{isExpanded ? '▼' : '▶'}</span>
        </div>
      </div>

      {isExpanded && (
        <div className="ngp-group-content">
          {editing ? (
            <div className="ngp-edit-form">
              <div className="ngp-field">
                <label>Group Name</label>
                <input
                  type="text"
                  value={editConfig.name}
                  onChange={(e) =>
                    setEditConfig((c) => ({ ...c, name: e.target.value }))
                  }
                />
              </div>
              <div className="ngp-field">
                <label>Replicas</label>
                <input
                  type="number"
                  min="1"
                  value={editConfig.replicas}
                  onChange={(e) =>
                    setEditConfig((c) => ({
                      ...c,
                      replicas: parseInt(e.target.value) || 1,
                    }))
                  }
                />
              </div>
              <div className="ngp-field">
                <label>Image</label>
                <input
                  type="text"
                  value={editConfig.image}
                  onChange={(e) =>
                    setEditConfig((c) => ({ ...c, image: e.target.value }))
                  }
                />
              </div>
              <div className="ngp-edit-actions">
                <button className="ngp-btn ngp-btn--secondary" onClick={handleCancel}>
                  Cancel
                </button>
                <button className="ngp-btn ngp-btn--primary" onClick={handleSave}>
                  Save
                </button>
              </div>
            </div>
          ) : (
            <>
              <div className="ngp-group-details">
                <div className="ngp-detail-row">
                  <span className="ngp-detail-label">Image:</span>
                  <span className="ngp-detail-value">{group.image}</span>
                </div>
                <div className="ngp-detail-row">
                  <span className="ngp-detail-label">Labels:</span>
                  <span className="ngp-detail-value">
                    {Object.entries(group.labels).map(([k, v]) => `${k}=${v}`).join(', ') || '-'}
                  </span>
                </div>
              </div>

              <div className="ngp-node-list">
                <label>Nodes in this group:</label>
                {groupNodes.length > 0 ? (
                  <ul className="ngp-nodes">
                    {groupNodes.map((node) => (
                      <li key={node.id} className="ngp-node-item">
                        <span className="ngp-node-name">{node.name}</span>
                        <button
                          className="ngp-node-remove"
                          onClick={() => onRemoveNode(node.id)}
                          title="Remove from group"
                        >
                          ×
                        </button>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <span className="ngp-empty-text">No nodes in this group</span>
                )}
              </div>

              <div className="ngp-group-footer">
                <button className="ngp-btn ngp-btn--secondary" onClick={() => setEditing(true)}>
                  Edit
                </button>
                <button className="ngp-btn ngp-btn--danger" onClick={onDelete}>
                  Delete Group
                </button>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}

interface CreateGroupFormProps {
  selectedNodeIds: string[];
  availableNodes: { id: string; name: string; role: NodeRole }[];
  onCreate: (name: string, nodeIds: string[], config: GroupConfig) => void;
  onCancel: () => void;
}

function CreateGroupForm({
  selectedNodeIds,
  availableNodes,
  onCreate,
  onCancel,
}: CreateGroupFormProps) {
  const [name, setName] = useState('');
  const [image, setImage] = useState('busybox');
  const [labels] = useState<Record<string, string>>({});
  const [errors, setErrors] = useState<ValidationError[]>([]);

  const selectedNodes = useMemo(
    () => availableNodes.filter((n) => selectedNodeIds.includes(n.id)),
    [availableNodes, selectedNodeIds]
  );

  // Auto-detect role from selected nodes
  const detectedRole = useMemo(() => {
    if (selectedNodes.length === 0) return 'custom';
    const roles = new Set(selectedNodes.map((n) => n.role));
    return roles.size === 1 ? selectedNodes[0].role : 'custom';
  }, [selectedNodes]);

  // Auto-generate name based on role
  const suggestedName = useMemo(() => {
    return `${detectedRole}-group-${Date.now().toString(36)}`;
  }, [detectedRole]);

  const validate = useCallback((): boolean => {
    const errs: ValidationError[] = [];

    if (!name.trim()) {
      errs.push({ field: 'name', message: 'Group name is required' });
    } else if (!/^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/.test(name)) {
      errs.push({
        field: 'name',
        message: 'Name must be lowercase alphanumeric with hyphens',
      });
    }

    if (selectedNodeIds.length === 0) {
      errs.push({ field: 'nodes', message: 'Select at least one node' });
    }

    setErrors(errs);
    return errs.length === 0;
  }, [name, selectedNodeIds.length]);

  const handleCreate = useCallback(() => {
    if (validate()) {
      onCreate(name, selectedNodeIds, {
        name,
        replicas: selectedNodeIds.length,
        image,
        labels: { role: detectedRole, ...labels },
      });
    }
  }, [validate, name, selectedNodeIds, image, labels, detectedRole, onCreate]);

  const getFieldError = (field: string): string | undefined => {
    return errors.find((e) => e.field === field)?.message;
  };

  return (
    <div className="ngp-create-form">
      <h4 className="ngp-create-title">Create New Group</h4>

      <div className="ngp-selected-nodes">
        <label>Selected Nodes ({selectedNodes.length})</label>
        {selectedNodes.length > 0 ? (
          <ul className="ngp-selected-list">
            {selectedNodes.map((node) => (
              <li key={node.id} className="ngp-selected-item">
                <span
                  className="ngp-node-role-dot"
                  style={{ backgroundColor: ROLE_COLORS[node.role] }}
                />
                <span>{node.name}</span>
              </li>
            ))}
          </ul>
        ) : (
          <span className="ngp-empty-text">No nodes selected. Use Shift+Click to select multiple nodes.</span>
        )}
        {getFieldError('nodes') && (
          <span className="ngp-error">{getFieldError('nodes')}</span>
        )}
      </div>

      <div className={`ngp-field ${getFieldError('name') ? 'ngp-field--error' : ''}`}>
        <label>Group Name</label>
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder={suggestedName}
        />
        {getFieldError('name') && (
          <span className="ngp-error">{getFieldError('name')}</span>
        )}
      </div>

      <div className="ngp-field">
        <label>Detected Role</label>
        <div className="ngp-role-badge" style={{ backgroundColor: ROLE_COLORS[detectedRole] }}>
          {ROLE_LABELS[detectedRole]}
        </div>
      </div>

      <div className="ngp-field">
        <label>Image</label>
        <input
          type="text"
          value={image}
          onChange={(e) => setImage(e.target.value)}
          placeholder="e.g., nginx:alpine"
        />
      </div>

      <div className="ngp-create-actions">
        <button className="ngp-btn ngp-btn--secondary" onClick={onCancel}>
          Cancel
        </button>
        <button
          className="ngp-btn ngp-btn--primary"
          onClick={handleCreate}
          disabled={selectedNodeIds.length === 0}
        >
          Create Group
        </button>
      </div>
    </div>
  );
}

// ============================================================================
// Main Component
// ============================================================================

function NodeGroupPanel({
  groups,
  selectedNodeIds,
  availableNodes,
  onCreateGroup,
  onUpdateGroup,
  onDeleteGroup,
  onAddNodesToGroup: _onAddNodesToGroup,
  onRemoveNodeFromGroup,
  onClose,
}: NodeGroupPanelProps) {
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set());

  const toggleGroup = useCallback((groupId: string) => {
    setExpandedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(groupId)) {
        next.delete(groupId);
      } else {
        next.add(groupId);
      }
      return next;
    });
  }, []);

  const handleCreateGroup = useCallback(
    (name: string, nodeIds: string[], config: GroupConfig) => {
      onCreateGroup(name, nodeIds, config);
      setShowCreateForm(false);
    },
    [onCreateGroup]
  );

  // Group nodes that are not in any group
  const ungroupedNodes = useMemo(() => {
    const groupedNodeIds = new Set(groups.flatMap((g) => g.nodeIds));
    return availableNodes.filter((n) => !groupedNodeIds.has(n.id));
  }, [availableNodes, groups]);

  return (
    <div className="node-group-panel">
      <div className="ngp-header">
        <h3 className="ngp-title">Node Groups</h3>
        {onClose && (
          <button className="ngp-close" onClick={onClose} title="Close">
            ×
          </button>
        )}
      </div>

      <div className="ngp-content">
        {showCreateForm ? (
          <CreateGroupForm
            selectedNodeIds={selectedNodeIds}
            availableNodes={availableNodes}
            onCreate={handleCreateGroup}
            onCancel={() => setShowCreateForm(false)}
          />
        ) : (
          <>
            <div className="ngp-toolbar">
              <button
                className="ngp-btn ngp-btn--primary"
                onClick={() => setShowCreateForm(true)}
                disabled={selectedNodeIds.length === 0}
              >
                Create Group ({selectedNodeIds.length} selected)
              </button>
            </div>

            <div className="ngp-section">
              <h4 className="ngp-section-title">
                Groups ({groups.length})
              </h4>
              {groups.length > 0 ? (
                <div className="ngp-groups-list">
                  {groups.map((group) => (
                    <GroupCard
                      key={group.id}
                      group={group}
                      nodes={availableNodes}
                      onUpdate={(config) => onUpdateGroup(group.id, config)}
                      onDelete={() => onDeleteGroup(group.id)}
                      onRemoveNode={(nodeId) => onRemoveNodeFromGroup(group.id, nodeId)}
                      isExpanded={expandedGroups.has(group.id)}
                      onToggle={() => toggleGroup(group.id)}
                    />
                  ))}
                </div>
              ) : (
                <div className="ngp-empty">
                  <span className="ngp-empty-icon">📦</span>
                  <span className="ngp-empty-text">No groups created yet</span>
                  <span className="ngp-empty-hint">Select nodes and click "Create Group"</span>
                </div>
              )}
            </div>

            <div className="ngp-section">
              <h4 className="ngp-section-title">
                Ungrouped Nodes ({ungroupedNodes.length})
              </h4>
              {ungroupedNodes.length > 0 ? (
                <ul className="ngp-ungrouped-list">
                  {ungroupedNodes.map((node) => (
                    <li key={node.id} className="ngp-ungrouped-item">
                      <span
                        className="ngp-node-role-dot"
                        style={{ backgroundColor: ROLE_COLORS[node.role] }}
                      />
                      <span className="ngp-ungrouped-name">{node.name}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <span className="ngp-empty-text">All nodes are in groups</span>
              )}
            </div>
          </>
        )}
      </div>

      <div className="ngp-footer">
        <span className="ngp-hint">💡 Tip: Use Shift+Click to select multiple nodes</span>
      </div>
    </div>
  );
}

export default memo(NodeGroupPanel);
