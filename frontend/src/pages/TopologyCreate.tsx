import { useState, useCallback, useEffect, useMemo } from 'react';
import Editor from '@monaco-editor/react';
import yaml from 'js-yaml';
import 'reactflow/dist/style.css';
import type { NetworkTopology, NodeGroup } from '../types/api';
import { apiClient } from '../api/client';
import VisualEditor from '../components/topology/VisualEditor';
import ConfigPanel from '../components/topology/ConfigPanel';
import './TopologyCreate.css';

// ============================================================================
// Types
// ============================================================================

type EditorMode = 'visual' | 'yaml';

interface TopologyCreateProps {
  onCreated?: (name: string, namespace: string) => void;
  onCancel?: () => void;
  isEdit?: boolean;
  initialTopology?: NetworkTopology;
}

// ============================================================================
// Constants
// ============================================================================

const DEFAULT_NAMESPACE = 'kuro-experiment';
const DEFAULT_IMAGE = 'busybox:latest';

// Generate unique topology name
function generateTopologyName(): string {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let suffix = '';
  for (let i = 0; i < 6; i++) {
    suffix += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return `topology-${suffix}`;
}

// Default node groups
const DEFAULT_NODE_GROUPS: NodeGroup[] = [
  {
    name: 'leader',
    replicas: 1,
    image: DEFAULT_IMAGE,
    labels: { role: 'leader' },
  },
  {
    name: 'follower',
    replicas: 2,
    image: DEFAULT_IMAGE,
    labels: { role: 'follower' },
  },
];

// ============================================================================
// YAML Utilities
// ============================================================================

function topologyToYaml(topology: NetworkTopology): string {
  return yaml.dump(topology, {
    indent: 2,
    lineWidth: -1,
    noRefs: true,
    quotingType: '"',
    forceQuotes: false,
  });
}

function yamlToTopology(yamlContent: string): { topology: NetworkTopology | null; error: string | null } {
  try {
    const parsed = yaml.load(yamlContent) as unknown;

    if (!parsed || typeof parsed !== 'object') {
      return { topology: null, error: 'Invalid YAML structure' };
    }

    const topology = parsed as NetworkTopology;

    // Basic validation
    if (topology.kind !== 'NetworkTopology') {
      return { topology: null, error: 'Kind must be NetworkTopology' };
    }

    if (!topology.metadata?.name) {
      return { topology: null, error: 'metadata.name is required' };
    }

    if (!topology.spec?.nodeGroups || !Array.isArray(topology.spec.nodeGroups)) {
      return { topology: null, error: 'spec.nodeGroups array is required' };
    }

    if (topology.spec.nodeGroups.length === 0) {
      return { topology: null, error: 'At least one nodeGroup is required' };
    }

    // Validate each nodeGroup
    for (const group of topology.spec.nodeGroups) {
      if (!group.name) {
        return { topology: null, error: 'Each nodeGroup must have a name' };
      }
      if (!group.image) {
        return { topology: null, error: `NodeGroup "${group.name}" must have an image` };
      }
    }

    return { topology, error: null };
  } catch (e) {
    const errorMessage = e instanceof Error ? e.message : 'Unknown parsing error';
    return { topology: null, error: errorMessage };
  }
}

function buildTopologyFromState(
  name: string,
  namespace: string,
  nodeGroups: NodeGroup[]
): NetworkTopology {
  return {
    apiVersion: 'simulation.kuro.io/v1alpha1',
    kind: 'NetworkTopology',
    metadata: {
      name,
      namespace,
      uid: '',
      creationTimestamp: new Date().toISOString(),
    },
    spec: {
      nodeGroups,
    },
  };
}

// ============================================================================
// Main Component
// ============================================================================

export function TopologyCreate({ onCreated, onCancel, isEdit = false, initialTopology }: TopologyCreateProps) {
  // Editor mode state
  const [mode, setMode] = useState<EditorMode>('visual');

  // Shared topology state
  const [name, setName] = useState(() => {
    if (initialTopology?.metadata?.name) return initialTopology.metadata.name;
    return generateTopologyName();
  });
  const [namespace, setNamespace] = useState(() => {
    if (initialTopology?.metadata?.namespace) return initialTopology.metadata.namespace;
    return DEFAULT_NAMESPACE;
  });
  const [nodeGroups, setNodeGroups] = useState<NodeGroup[]>(() => {
    if (initialTopology?.spec?.nodeGroups) return initialTopology.spec.nodeGroups;
    return DEFAULT_NODE_GROUPS;
  });

  // YAML mode state
  const [yamlContent, setYamlContent] = useState(() => {
    if (initialTopology) {
      return topologyToYaml(initialTopology);
    }
    return topologyToYaml(buildTopologyFromState(name, namespace, nodeGroups));
  });

  // Selection state for visual editor
  const [selectedGroupId, setSelectedGroupId] = useState<string | null>(null);

  // UI state
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  // Build topology object from current state
  const currentTopology = useMemo(() => {
    return buildTopologyFromState(name, namespace, nodeGroups);
  }, [name, namespace, nodeGroups]);

  // Sync YAML content when switching to YAML mode
  useEffect(() => {
    if (mode === 'yaml') {
      setYamlContent(topologyToYaml(currentTopology));
    }
  }, [mode, currentTopology]);

  // Handle mode toggle
  const handleModeChange = useCallback((newMode: EditorMode) => {
    if (newMode === 'yaml') {
      // Update YAML from current visual state
      setYamlContent(topologyToYaml(currentTopology));
    }
    setMode(newMode);
    setError(null);
  }, [currentTopology]);

  // Handle YAML editor change
  const handleYamlChange = useCallback((value: string | undefined) => {
    const content = value || '';
    setYamlContent(content);

    // Parse and update visual state
    const { topology, error: parseError } = yamlToTopology(content);
    if (parseError) {
      setError(parseError);
    } else if (topology) {
      setError(null);
      setName(topology.metadata.name);
      setNamespace(topology.metadata.namespace || DEFAULT_NAMESPACE);
      setNodeGroups(topology.spec.nodeGroups);
    }
  }, []);

  // Handle visual editor changes
  const handleAddGroup = useCallback(() => {
    const newGroupNumber = nodeGroups.length + 1;
    const newGroup: NodeGroup = {
      name: `group-${newGroupNumber}`,
      replicas: 1,
      image: DEFAULT_IMAGE,
      labels: { role: `role-${newGroupNumber}` },
    };
    setNodeGroups([...nodeGroups, newGroup]);
    setSelectedGroupId(newGroup.name);
  }, [nodeGroups]);

  const handleDeleteGroup = useCallback((groupId: string) => {
    setNodeGroups(prev => prev.filter(g => g.name !== groupId));
    if (selectedGroupId === groupId) {
      setSelectedGroupId(null);
    }
  }, [selectedGroupId]);

  const handleUpdateGroup = useCallback((groupId: string, updates: Partial<NodeGroup>) => {
    setNodeGroups(prev => prev.map(g => {
      if (g.name !== groupId) return g;
      
      // Handle name change - need to update group name
      if (updates.name && updates.name !== groupId) {
        return { ...g, ...updates };
      }
      return { ...g, ...updates };
    }));
  }, []);

  // Handle submit
  const handleSubmit = useCallback(async () => {
    const topology = currentTopology;
    
    setCreating(true);
    setCreateError(null);
    
    try {
      let response;
      if (isEdit) {
        response = await apiClient.updateTopology(topology);
      } else {
        response = await apiClient.createTopology(topology);
      }
      
      if (response.success) {
        console.log(isEdit ? 'Topology updated successfully:' : 'Topology created successfully:', response.data);
        onCreated?.(name, namespace);
      } else {
        setCreateError(response.error || `Failed to ${isEdit ? 'update' : 'create'} topology`);
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setCreateError(errorMessage);
      console.error(`Failed to ${isEdit ? 'update' : 'create'} topology:`, err);
    } finally {
      setCreating(false);
    }
  }, [currentTopology, isEdit, name, namespace, onCreated]);

  // Handle import from session storage (topology import feature)
  useEffect(() => {
    const importedTopologyJson = sessionStorage.getItem('importedTopology');
    if (importedTopologyJson) {
      try {
        const importedTopology = JSON.parse(importedTopologyJson) as NetworkTopology;
        setName(importedTopology.metadata.name);
        setNamespace(importedTopology.metadata.namespace || DEFAULT_NAMESPACE);
        setNodeGroups(importedTopology.spec.nodeGroups);
        setYamlContent(topologyToYaml(importedTopology));
        sessionStorage.removeItem('importedTopology');
      } catch {
        console.error('Failed to parse imported topology');
      }
    }
  }, []);

  // Calculate stats
  const totalNodes = nodeGroups.reduce((sum, g) => sum + g.replicas, 0);
  const groupCount = nodeGroups.length;

  return (
    <div className="topology-create">
      {/* Header */}
      <div className="create-header">
        <div className="create-header-left">
          {onCancel && (
            <button className="btn-back" onClick={onCancel} disabled={creating}>
              ← Back
            </button>
          )}
          <h2>{isEdit ? 'Edit Topology' : 'Create Topology'}</h2>
        </div>
        <div className="create-header-right">
          {/* Mode Toggle */}
          <div className="mode-toggle">
            <button
              className={`mode-btn ${mode === 'visual' ? 'active' : ''}`}
              onClick={() => handleModeChange('visual')}
            >
              Visual
            </button>
            <button
              className={`mode-btn ${mode === 'yaml' ? 'active' : ''}`}
              onClick={() => handleModeChange('yaml')}
            >
              YAML
            </button>
          </div>
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="error-banner">
          <span className="error-icon">⚠</span>
          <span className="error-message">{error}</span>
        </div>
      )}

      {createError && (
        <div className="error-banner">
          <span className="error-icon">❌</span>
          <span className="error-message">{createError}</span>
        </div>
      )}

      {/* Content */}
      <div className="create-content">
        {mode === 'visual' ? (
          <>
            {/* Visual Editor Panel */}
            <div className="visual-panel">
              <div className="panel-header">
                <h3>Topology Editor</h3>
                <div className="panel-stats">
                  <span className="stat">{groupCount} groups</span>
                  <span className="stat">{totalNodes} nodes</span>
                </div>
              </div>
              <div className="visual-panel-content">
                <VisualEditor
                  nodeGroups={nodeGroups}
                  selectedGroupId={selectedGroupId}
                  onSelectGroup={setSelectedGroupId}
                  onAddGroup={handleAddGroup}
                />
              </div>
            </div>

            {/* Config Panel */}
            <ConfigPanel
              name={name}
              namespace={namespace}
              nodeGroups={nodeGroups}
              selectedGroupId={selectedGroupId}
              onNameChange={setName}
              onNamespaceChange={setNamespace}
              onAddGroup={handleAddGroup}
              onSelectGroup={setSelectedGroupId}
              onDeleteGroup={handleDeleteGroup}
              onUpdateGroup={handleUpdateGroup}
              onSubmit={handleSubmit}
              submitLabel={isEdit ? 'Update Topology' : 'Create Topology'}
              isSubmitting={creating}
            />
          </>
        ) : (
          /* YAML Editor Panel */
          <div className="yaml-panel">
            <div className="panel-header">
              <h3>YAML Editor</h3>
              <span className="hint">Edit the topology definition</span>
              <div className="yaml-actions">
                <button
                  className="btn-primary"
                  onClick={handleSubmit}
                  disabled={!!error || creating}
                >
                  {creating ? (isEdit ? 'Updating...' : 'Creating...') : (isEdit ? 'Update Topology' : 'Create Topology')}
                </button>
              </div>
            </div>
            <div className="yaml-editor-container">
              <Editor
                height="100%"
                defaultLanguage="yaml"
                value={yamlContent}
                onChange={handleYamlChange}
                theme="vs-dark"
                options={{
                  minimap: { enabled: false },
                  fontSize: 14,
                  lineNumbers: 'on',
                  wordWrap: 'on',
                  automaticLayout: true,
                  scrollBeyondLastLine: false,
                  tabSize: 2,
                }}
              />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default TopologyCreate;