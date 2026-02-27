import { useState, useReducer, useCallback, memo, useMemo, useRef, useEffect } from 'react';
import type { TopologyNode, NodeRole } from '../../types/api';
import './NodeConfigPanel.css';

// ============================================================================
// Types
// ============================================================================

export interface NodeConfig {
  name: string;
  role: NodeRole;
  image: string;
  labels: Record<string, string>;
  replicas: number;
  resources?: {
    cpu?: string;
    memory?: string;
  };
  command?: string[];
  env?: Record<string, string>;
}

export interface NodeConfigPanelProps {
  node: TopologyNode | null;
  onConfigChange?: (nodeId: string, config: Partial<NodeConfig>) => void;
  onDelete?: (nodeId: string) => void;
  onClose?: () => void;
}

interface ValidationError {
  field: string;
  message: string;
}

// ============================================================================
// Constants
// ============================================================================

const DEFAULT_IMAGES: Record<NodeRole, string> = {
  drone: 'nicolaka/netshoot',
  'ground-station': 'nicolaka/netshoot',
  gateway: 'nicolaka/netshoot',
  server: 'nginx:alpine',
  client: 'busybox',
  custom: 'busybox',
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

interface FormFieldProps {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  error?: string;
  type?: 'text' | 'number';
  disabled?: boolean;
  hint?: string;
}

function FormField({
  label,
  value,
  onChange,
  placeholder,
  error,
  type = 'text',
  disabled,
  hint,
}: FormFieldProps) {
  return (
    <div className={`ncp-field ${error ? 'ncp-field--error' : ''}`}>
      <label className="ncp-field__label">{label}</label>
      <input
        type={type}
        className="ncp-field__input"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        disabled={disabled}
      />
      {hint && !error && <span className="ncp-field__hint">{hint}</span>}
      {error && <span className="ncp-field__error">{error}</span>}
    </div>
  );
}

interface LabelsEditorProps {
  labels: Record<string, string>;
  onChange: (labels: Record<string, string>) => void;
}

function LabelsEditor({ labels, onChange }: LabelsEditorProps) {
  const [newKey, setNewKey] = useState('');
  const [newValue, setNewValue] = useState('');

  const handleAddLabel = useCallback(() => {
    if (newKey.trim() && newValue.trim()) {
      onChange({
        ...labels,
        [newKey.trim()]: newValue.trim(),
      });
      setNewKey('');
      setNewValue('');
    }
  }, [labels, newKey, newValue, onChange]);

  const handleRemoveLabel = useCallback(
    (key: string) => {
      const updated = { ...labels };
      delete updated[key];
      onChange(updated);
    },
    [labels, onChange]
  );

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        handleAddLabel();
      }
    },
    [handleAddLabel]
  );

  const labelEntries = Object.entries(labels);

  return (
    <div className="ncp-labels">
      <label className="ncp-field__label">Labels</label>
      <div className="ncp-labels__list">
        {labelEntries.map(([key, value]) => (
          <div key={key} className="ncp-labels__item">
            <span className="ncp-labels__key">{key}</span>
            <span className="ncp-labels__sep">:</span>
            <span className="ncp-labels__value">{value}</span>
            <button
              className="ncp-labels__remove"
              onClick={() => handleRemoveLabel(key)}
              title="Remove label"
            >
              ×
            </button>
          </div>
        ))}
      </div>
      <div className="ncp-labels__add">
        <input
          type="text"
          className="ncp-field__input ncp-labels__input"
          placeholder="Key"
          value={newKey}
          onChange={(e) => setNewKey(e.target.value)}
          onKeyDown={handleKeyDown}
        />
        <input
          type="text"
          className="ncp-field__input ncp-labels__input"
          placeholder="Value"
          value={newValue}
          onChange={(e) => setNewValue(e.target.value)}
          onKeyDown={handleKeyDown}
        />
        <button
          className="ncp-btn ncp-btn--small"
          onClick={handleAddLabel}
          disabled={!newKey.trim() || !newValue.trim()}
        >
          Add
        </button>
      </div>
    </div>
  );
}

interface ResourcesEditorProps {
  resources?: { cpu?: string; memory?: string };
  onChange: (resources: { cpu?: string; memory?: string }) => void;
}

function ResourcesEditor({ resources, onChange }: ResourcesEditorProps) {
  return (
    <div className="ncp-resources">
      <label className="ncp-field__label">Resources</label>
      <div className="ncp-resources__fields">
        <div className="ncp-field">
          <label className="ncp-field__label ncp-field__label--small">CPU</label>
          <input
            type="text"
            className="ncp-field__input"
            placeholder="e.g., 100m, 0.5"
            value={resources?.cpu || ''}
            onChange={(e) => onChange({ ...resources, cpu: e.target.value || undefined })}
          />
        </div>
        <div className="ncp-field">
          <label className="ncp-field__label ncp-field__label--small">Memory</label>
          <input
            type="text"
            className="ncp-field__input"
            placeholder="e.g., 128Mi, 1Gi"
            value={resources?.memory || ''}
            onChange={(e) => onChange({ ...resources, memory: e.target.value || undefined })}
          />
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// Main Component
// ============================================================================

// Get initial config from node
function getInitialConfig(node: TopologyNode | null): NodeConfig {
  if (node) {
    return {
      name: node.name,
      role: node.role,
      image: DEFAULT_IMAGES[node.role] || 'busybox',
      labels: { ...node.labels },
      replicas: 1,
      resources: {},
    };
  }
  return {
    name: '',
    role: 'custom',
    image: '',
    labels: {},
    replicas: 1,
    resources: {},
  };
}

// State type for reducer
interface PanelState {
  config: NodeConfig;
  errors: ValidationError[];
  hasChanges: boolean;
}

// Action types
type PanelAction =
  | { type: 'UPDATE_CONFIG'; config: Partial<NodeConfig>; errors: ValidationError[] }
  | { type: 'SYNC_NODE'; config: NodeConfig }
  | { type: 'CLEAR_CHANGES' };

// Reducer function
function panelReducer(state: PanelState, action: PanelAction): PanelState {
  switch (action.type) {
    case 'UPDATE_CONFIG':
      return {
        config: { ...state.config, ...action.config },
        errors: action.errors,
        hasChanges: true,
      };
    case 'SYNC_NODE':
      return {
        config: action.config,
        errors: [],
        hasChanges: false,
      };
    case 'CLEAR_CHANGES':
      return {
        ...state,
        hasChanges: false,
      };
    default:
      return state;
  }
}

function NodeConfigPanel({ node, onConfigChange, onDelete, onClose }: NodeConfigPanelProps) {
  // Calculate initial config from node
  const initialConfig = useMemo(() => getInitialConfig(node), [node]);
  
  // Use reducer to manage panel state
  const [state, dispatch] = useReducer(panelReducer, {
    config: initialConfig,
    errors: [],
    hasChanges: false,
  });

  // Track previous node id to detect changes
  const prevNodeIdRef = useRef(node?.id);

  // Update config when node changes (different node selected)
  useEffect(() => {
    const nodeChanged = prevNodeIdRef.current !== node?.id;
    
    if (nodeChanged) {
      prevNodeIdRef.current = node?.id;
      dispatch({ type: 'SYNC_NODE', config: getInitialConfig(node) });
    }
  }, [node]);

  // Destructure state for easier access
  const { config, errors, hasChanges } = state;

  // Validate config
  const validateConfig = useCallback((cfg: NodeConfig): ValidationError[] => {
    const errs: ValidationError[] = [];

    if (!cfg.name.trim()) {
      errs.push({ field: 'name', message: 'Name is required' });
    } else if (!/^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/.test(cfg.name)) {
      errs.push({
        field: 'name',
        message: 'Name must be lowercase alphanumeric with hyphens',
      });
    }

    if (!cfg.image.trim()) {
      errs.push({ field: 'image', message: 'Image is required' });
    }

    if (cfg.replicas < 1) {
      errs.push({ field: 'replicas', message: 'Replicas must be at least 1' });
    }

    return errs;
  }, []);

  // Handle config update
  const updateConfig = useCallback(
    (updates: Partial<NodeConfig>) => {
      const newConfig = { ...config, ...updates };
      dispatch({ type: 'UPDATE_CONFIG', config: updates, errors: validateConfig(newConfig) });
    },
    [config, validateConfig]
  );

  // Handle save
  const handleSave = useCallback(() => {
    const errs = validateConfig(config);
    
    if (errs.length === 0 && node && onConfigChange) {
      onConfigChange(node.id, config);
      dispatch({ type: 'CLEAR_CHANGES' });
    }
  }, [config, node, onConfigChange, validateConfig]);

  // Handle delete
  const handleDelete = useCallback(() => {
    if (node && onDelete) {
      onDelete(node.id);
    }
  }, [node, onDelete]);

  // Get error for field
  const getFieldError = (field: string): string | undefined => {
    return errors.find((e) => e.field === field)?.message;
  };

  if (!node) {
    return (
      <div className="node-config-panel node-config-panel--empty">
        <div className="ncp-empty">
          <span className="ncp-empty__icon">⚙️</span>
          <span className="ncp-empty__text">Select a node to configure</span>
        </div>
      </div>
    );
  }

  return (
    <div className="node-config-panel">
      <div className="ncp-header">
        <h3 className="ncp-title">Node Configuration</h3>
        {onClose && (
          <button className="ncp-close" onClick={onClose} title="Close">
            ×
          </button>
        )}
      </div>

      <div className="ncp-node-info">
        <span className="ncp-node-info__role">{ROLE_LABELS[config.role]}</span>
        <span className="ncp-node-info__id">ID: {node.id}</span>
      </div>

      <div className="ncp-form">
        <FormField
          label="Name"
          value={config.name}
          onChange={(value) => updateConfig({ name: value })}
          placeholder="node-name"
          error={getFieldError('name')}
          hint="Lowercase alphanumeric with hyphens"
        />

        <div className="ncp-field">
          <label className="ncp-field__label">Role</label>
          <div className="ncp-field__value ncp-field__value--readonly">{ROLE_LABELS[config.role]}</div>
        </div>

        <FormField
          label="Image"
          value={config.image}
          onChange={(value) => updateConfig({ image: value })}
          placeholder="e.g., nginx:alpine"
          error={getFieldError('image')}
        />

        <FormField
          label="Replicas"
          value={config.replicas.toString()}
          onChange={(value) => updateConfig({ replicas: parseInt(value) || 1 })}
          type="number"
          error={getFieldError('replicas')}
        />

        <LabelsEditor
          labels={config.labels}
          onChange={(labels) => updateConfig({ labels })}
        />

        <ResourcesEditor
          resources={config.resources}
          onChange={(resources) => updateConfig({ resources })}
        />
      </div>

      <div className="ncp-actions">
        <button className="ncp-btn ncp-btn--danger" onClick={handleDelete}>
          Delete Node
        </button>
        <button
          className="ncp-btn ncp-btn--primary"
          onClick={handleSave}
          disabled={!hasChanges || errors.length > 0}
        >
          Apply Changes
        </button>
      </div>

      {hasChanges && errors.length === 0 && (
        <div className="ncp-unsaved">You have unsaved changes</div>
      )}
    </div>
  );
}

export default memo(NodeConfigPanel);
