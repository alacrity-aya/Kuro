import { memo, useCallback } from 'react';
import type { NodeGroup } from '../../types/api';
import './ConfigPanel.css';

// ============================================================================
// Types
// ============================================================================

export interface ConfigPanelProps {
  /** Topology name */
  name: string;
  /** Kubernetes namespace */
  namespace: string;
  /** List of node groups in the topology */
  nodeGroups: NodeGroup[];
  /** Currently selected group ID (group name) */
  selectedGroupId: string | null;
  /** Handler for name changes */
  onNameChange: (name: string) => void;
  /** Handler for namespace changes */
  onNamespaceChange: (namespace: string) => void;
  /** Handler to add a new group */
  onAddGroup: () => void;
  /** Handler to select a group */
  onSelectGroup: (groupId: string) => void;
  /** Handler to delete a group */
  onDeleteGroup: (groupId: string) => void;
  /** Handler to update a group's properties */
  onUpdateGroup: (groupId: string, updates: Partial<NodeGroup>) => void;
  /** Handler for submit action */
  onSubmit: () => void;
  /** Label for the submit button */
  submitLabel?: string;
  /** Whether the form is submitting */
  isSubmitting?: boolean;
}

// ============================================================================
// Constants
// ============================================================================

const DEFAULT_NAMESPACE = 'kuro-experiment';

const GROUP_COLORS = [
  '#3b82f6', // blue
  '#10b981', // green
  '#f59e0b', // amber
  '#8b5cf6', // purple
  '#ec4899', // pink
  '#06b6d4', // cyan
];

// ============================================================================
// Sub-Components
// ============================================================================

interface BasicInfoSectionProps {
  name: string;
  namespace: string;
  onNameChange: (name: string) => void;
  onNamespaceChange: (namespace: string) => void;
}

function BasicInfoSection({
  name,
  namespace,
  onNameChange,
  onNamespaceChange,
}: BasicInfoSectionProps) {
  return (
    <section className="config-section">
      <h3 className="config-section-title">Basic Info</h3>
      <div className="config-field">
        <label htmlFor="topology-name">Name</label>
        <input
          id="topology-name"
          type="text"
          value={name}
          onChange={(e) => onNameChange(e.target.value)}
          placeholder="my-topology"
        />
      </div>
      <div className="config-field">
        <label htmlFor="topology-namespace">Namespace</label>
        <input
          id="topology-namespace"
          type="text"
          value={namespace}
          onChange={(e) => onNamespaceChange(e.target.value)}
          placeholder={DEFAULT_NAMESPACE}
        />
      </div>
    </section>
  );
}

interface GroupItemProps {
  group: NodeGroup;
  index: number;
  isSelected: boolean;
  onSelect: () => void;
  onDelete: () => void;
}

function GroupItem({ group, index, isSelected, onSelect, onDelete }: GroupItemProps) {
  const color = GROUP_COLORS[index % GROUP_COLORS.length];
  
  const handleDelete = useCallback((e: React.MouseEvent) => {
    e.stopPropagation();
    onDelete();
  }, [onDelete]);

  return (
    <div
      className={`config-group-item ${isSelected ? 'selected' : ''}`}
      onClick={onSelect}
      style={{ '--group-color': color } as React.CSSProperties}
    >
      <div className="config-group-color" style={{ backgroundColor: color }} />
      <div className="config-group-info">
        <span className="config-group-name">{group.name}</span>
        <span className="config-group-meta">
          {group.replicas} {group.replicas === 1 ? 'replica' : 'replicas'}
        </span>
      </div>
      <button
        className="config-group-delete"
        onClick={handleDelete}
        title="Delete group"
      >
        ×
      </button>
    </div>
  );
}

interface NodeGroupsSectionProps {
  nodeGroups: NodeGroup[];
  selectedGroupId: string | null;
  onAddGroup: () => void;
  onSelectGroup: (groupId: string) => void;
  onDeleteGroup: (groupId: string) => void;
}

function NodeGroupsSection({
  nodeGroups,
  selectedGroupId,
  onAddGroup,
  onSelectGroup,
  onDeleteGroup,
}: NodeGroupsSectionProps) {
  return (
    <section className="config-section">
      <div className="config-section-header">
        <h3 className="config-section-title">Node Groups</h3>
        <button className="config-add-btn" onClick={onAddGroup} title="Add group">
          + Add
        </button>
      </div>
      <div className="config-groups-list">
        {nodeGroups.length === 0 ? (
          <div className="config-empty">
            <span className="config-empty-icon">📦</span>
            <span className="config-empty-text">No node groups</span>
            <span className="config-empty-hint">Click "Add" to create a group</span>
          </div>
        ) : (
          nodeGroups.map((group, index) => (
            <GroupItem
              key={group.name}
              group={group}
              index={index}
              isSelected={selectedGroupId === group.name}
              onSelect={() => onSelectGroup(group.name)}
              onDelete={() => onDeleteGroup(group.name)}
            />
          ))
        )}
      </div>
    </section>
  );
}

interface EditSectionProps {
  group: NodeGroup | undefined;
  onUpdateGroup: (updates: Partial<NodeGroup>) => void;
}

function EditSection({ group, onUpdateGroup }: EditSectionProps) {
  if (!group) {
    return (
      <section className="config-section config-edit-section">
        <h3 className="config-section-title">Edit Group</h3>
        <div className="config-edit-empty">
          <span className="config-edit-empty-text">Select a group to edit</span>
        </div>
      </section>
    );
  }

  const handleRoleChange = (role: string) => {
    onUpdateGroup({
      labels: {
        ...group.labels,
        role,
      },
    });
  };

  return (
    <section className="config-section config-edit-section">
      <h3 className="config-section-title">Edit: {group.name}</h3>
      <div className="config-edit-form">
        <div className="config-field">
          <label htmlFor="group-name">Group Name</label>
          <input
            id="group-name"
            type="text"
            value={group.name}
            onChange={(e) => onUpdateGroup({ name: e.target.value })}
            placeholder="group-name"
          />
        </div>
        <div className="config-field">
          <label htmlFor="group-replicas">Replicas</label>
          <input
            id="group-replicas"
            type="number"
            min="1"
            value={group.replicas}
            onChange={(e) => onUpdateGroup({ replicas: parseInt(e.target.value) || 1 })}
          />
        </div>
        <div className="config-field">
          <label htmlFor="group-image">Image</label>
          <input
            id="group-image"
            type="text"
            value={group.image}
            onChange={(e) => onUpdateGroup({ image: e.target.value })}
            placeholder="busybox:latest"
          />
        </div>
        <div className="config-field">
          <label htmlFor="group-role">Role Label</label>
          <input
            id="group-role"
            type="text"
            value={group.labels?.role || ''}
            onChange={(e) => handleRoleChange(e.target.value)}
            placeholder="drone"
          />
        </div>
        <div className="config-field">
          <label htmlFor="group-command">Command</label>
          <input
            id="group-command"
            type="text"
            value={group.command?.join(' ') || ''}
            onChange={(e) => onUpdateGroup({
              command: e.target.value ? e.target.value.split(/\s+/).filter(Boolean) : undefined,
            })}
            placeholder="sleep infinite"
          />
          <span className="config-field-hint">Container startup command (space-separated)</span>
        </div>
      </div>
    </section>
  );
}

// ============================================================================
// Main Component
// ============================================================================

function ConfigPanel({
  name,
  namespace,
  nodeGroups,
  selectedGroupId,
  onNameChange,
  onNamespaceChange,
  onAddGroup,
  onSelectGroup,
  onDeleteGroup,
  onUpdateGroup,
  onSubmit,
  submitLabel = 'Create Topology',
  isSubmitting = false,
}: ConfigPanelProps) {
  const selectedGroup = nodeGroups.find((g) => g.name === selectedGroupId);

  const handleUpdateGroup = useCallback(
    (updates: Partial<NodeGroup>) => {
      if (selectedGroupId) {
        onUpdateGroup(selectedGroupId, updates);
      }
    },
    [selectedGroupId, onUpdateGroup]
  );

  return (
    <div className="config-panel">
      <div className="config-panel-content">
        <BasicInfoSection
          name={name}
          namespace={namespace}
          onNameChange={onNameChange}
          onNamespaceChange={onNamespaceChange}
        />
        <NodeGroupsSection
          nodeGroups={nodeGroups}
          selectedGroupId={selectedGroupId}
          onAddGroup={onAddGroup}
          onSelectGroup={onSelectGroup}
          onDeleteGroup={onDeleteGroup}
        />
        <EditSection group={selectedGroup} onUpdateGroup={handleUpdateGroup} />
      </div>
      <div className="config-panel-footer">
        <button
          className="config-submit-btn"
          onClick={onSubmit}
          disabled={isSubmitting || !name || nodeGroups.length === 0}
        >
          {isSubmitting ? 'Submitting...' : submitLabel}
        </button>
      </div>
    </div>
  );
}

export default memo(ConfigPanel);
