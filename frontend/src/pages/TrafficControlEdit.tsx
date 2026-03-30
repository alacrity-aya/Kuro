import { useState, useEffect, useCallback } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { apiClient } from '../api/client';
import { validatePolicy, type PolicyValidationResult } from '../utils/policyValidator';
import { exportTrafficControlToYaml, downloadYaml } from '../utils/trafficControlYaml';
import type { NetworkTopology, TrafficControl, NodeGroup } from '../types/api';
import './TrafficControlEdit.css';

interface TrafficControlEditProps {
  onSaved?: (name: string, namespace: string) => void;
  onCancel?: () => void;
}

function TrafficControlEdit({ onSaved, onCancel }: TrafficControlEditProps) {
  const navigate = useNavigate();
  const { namespace = 'kuro-experiment', name = '' } = useParams<{ namespace: string; name: string }>();

  // Form state
  const [trafficControl, setTrafficControl] = useState<TrafficControl | null>(null);
  const [selectedTopology, setSelectedTopology] = useState('');
  const [sourceGroup, setSourceGroup] = useState('');
  const [destGroup, setDestGroup] = useState('');
  const [policy, setPolicy] = useState({
    bandwidth: '',
    latency: '',
    jitter: '',
    packetLoss: '',
  });

  // Data state
  const [topologies, setTopologies] = useState<NetworkTopology[]>([]);
  const [nodeGroups, setNodeGroups] = useState<NodeGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [policyErrors, setPolicyErrors] = useState<Record<string, string>>({});

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);

    // Load TrafficControl
    const tcResponse = await apiClient.getTrafficControl(name, namespace);
    if (!tcResponse.success || !tcResponse.data) {
      setError(tcResponse.error || `TrafficControl '${name}' not found`);
      setLoading(false);
      return;
    }

    const tc = tcResponse.data;
    setTrafficControl(tc);

    // Pre-populate form from existing data
    setPolicy({
      bandwidth: tc.spec.policy.bandwidth || '10Mbps',
      latency: tc.spec.policy.latency || '10ms',
      jitter: tc.spec.policy.jitter || '5ms',
      packetLoss: tc.spec.policy.packetLoss || '0.1%',
    });

    // Extract source and destination groups from labels
    const sourceGroupLabel = tc.spec.source.matchLabels['kuro.io/node-group'] || tc.spec.source.matchLabels['role'] || '';
    const destGroupLabel = tc.spec.destination.matchLabels['kuro.io/node-group'] || tc.spec.destination.matchLabels['role'] || '';
    setSourceGroup(sourceGroupLabel);
    setDestGroup(destGroupLabel);

    // Load topologies
    const topologiesResponse = await apiClient.listTopologies(namespace);
    if (topologiesResponse.success && topologiesResponse.data) {
      setTopologies(topologiesResponse.data.items);
    }

    setLoading(false);
  }, [name, namespace]);

  // Load TrafficControl and topologies on mount
  useEffect(() => {
    loadData();
  }, [loadData]);

  // Update node groups when topology changes
  useEffect(() => {
    if (selectedTopology) {
      const topology = topologies.find((t) => t.metadata.name === selectedTopology);
      if (topology?.spec?.nodeGroups) {
        setNodeGroups(topology.spec.nodeGroups);
      }
    } else {
      setNodeGroups([]);
    }
  }, [selectedTopology, topologies]);

  // Handle policy field change
  const handlePolicyChange = (field: keyof typeof policy, value: string) => {
    setPolicy((prev) => ({ ...prev, [field]: value }));
    if (policyErrors[field]) {
      setPolicyErrors((prev) => {
        const next = { ...prev };
        delete next[field];
        return next;
      });
    }
  };

  // Validate form
  const validateForm = (): string | null => {
    if (!sourceGroup) {
      return 'Please select a source node group';
    }
    if (!destGroup) {
      return 'Please select a destination node group';
    }
    if (sourceGroup === destGroup) {
      return 'Source and destination node groups must be different';
    }

    // Validate policy values
    const policyValidation: PolicyValidationResult = validatePolicy(policy);
    if (!policyValidation.isValid) {
      setPolicyErrors(policyValidation.errors);
      return 'Please fix the policy validation errors';
    }

    return null;
  };

  // Handle form submission
  const handleSubmit = async () => {
    const validationError = validateForm();
    if (validationError) {
      setError(validationError);
      return;
    }

    if (!trafficControl) return;

    setSaving(true);
    setError(null);

    // Build updated TrafficControl CRD
    const updatedTc: TrafficControl = {
      ...trafficControl,
      spec: {
        source: {
          matchLabels: {
            'kuro.io/node-group': sourceGroup,
          },
        },
        destination: {
          matchLabels: {
            'kuro.io/node-group': destGroup,
          },
        },
        policy: {
          bandwidth: policy.bandwidth,
          latency: policy.latency,
          jitter: policy.jitter,
          packetLoss: policy.packetLoss,
        },
      },
    };

    try {
      const response = await apiClient.updateTrafficControl(updatedTc);

      if (response.success && response.data) {
        if (onSaved) {
          onSaved(name, namespace);
        } else {
          navigate('/traffic-controls');
        }
      } else {
        setError(response.error || 'Failed to update traffic control');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      console.error('Failed to update traffic control:', err);
    } finally {
      setSaving(false);
    }
  };

  // Handle export
  const handleExport = () => {
    if (!trafficControl) return;

    // Create a merged TC with current form state for export
    const exportTc: TrafficControl = {
      ...trafficControl,
      spec: {
        source: {
          matchLabels: {
            'kuro.io/node-group': sourceGroup,
          },
        },
        destination: {
          matchLabels: {
            'kuro.io/node-group': destGroup,
          },
        },
        policy: {
          bandwidth: policy.bandwidth,
          latency: policy.latency,
          jitter: policy.jitter,
          packetLoss: policy.packetLoss,
        },
      },
    };

    const yaml = exportTrafficControlToYaml(exportTc);
    downloadYaml(yaml, `${name}.yaml`);
  };

  // Handle cancel
  const handleCancel = () => {
    if (onCancel) {
      onCancel();
    } else {
      navigate('/traffic-controls');
    }
  };

  if (loading) {
    return (
      <div className="tc-edit">
        <div className="tc-edit__loading">
          <div className="tc-edit__spinner" />
          <span>Loading traffic control...</span>
        </div>
      </div>
    );
  }

  if (error && !trafficControl) {
    return (
      <div className="tc-edit">
        <div className="tc-edit__error-page">
          <span className="tc-edit__error-icon">⚠️</span>
          <span className="tc-edit__error-message">{error}</span>
          <button className="btn btn--secondary" onClick={handleCancel}>
            ← Back to List
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="tc-edit">
      <header className="tc-edit__header">
        <div className="tc-edit__title-section">
          <h1 className="tc-edit__title">Edit Traffic Control</h1>
          <p className="tc-edit__subtitle">
            <span className="tc-edit__name-badge">{name}</span>
            <span className="tc-edit__namespace-badge">{namespace}</span>
          </p>
        </div>
        <div className="tc-edit__header-actions">
          <button className="btn btn--secondary" onClick={handleExport} disabled={saving}>
            <span className="btn__icon">📥</span>
            Export YAML
          </button>
          <button className="btn btn--secondary" onClick={handleCancel} disabled={saving}>
            Cancel
          </button>
          <button
            className="btn btn--primary"
            onClick={handleSubmit}
            disabled={saving}
          >
            {saving ? 'Saving...' : 'Save Changes'}
          </button>
        </div>
      </header>

      {error && (
        <div className="tc-edit__error">
          <span className="tc-edit__error-icon">⚠️</span>
          <span className="tc-edit__error-message">{error}</span>
        </div>
      )}

      <div className="tc-edit__content">
        <div className="tc-edit__form">
          {/* Basic Info Section */}
          <section className="form-section">
            <h2 className="form-section__title">Basic Information</h2>
            <div className="form-group">
              <label className="form-label" htmlFor="name">
                Name
              </label>
              <input
                id="name"
                type="text"
                className="form-input form-input--readonly"
                value={name}
                readOnly
              />
              <span className="form-hint">
                Name cannot be changed after creation
              </span>
            </div>

            <div className="form-group">
              <label className="form-label" htmlFor="namespace">
                Namespace
              </label>
              <input
                id="namespace"
                type="text"
                className="form-input form-input--readonly"
                value={namespace}
                readOnly
              />
            </div>
          </section>

          {/* Topology Selection Section */}
          <section className="form-section">
            <h2 className="form-section__title">Topology Selection (Optional)</h2>
            <div className="form-group">
              <label className="form-label" htmlFor="topology">
                Topology
              </label>
              <select
                id="topology"
                className="form-select"
                value={selectedTopology}
                onChange={(e) => setSelectedTopology(e.target.value)}
                disabled={saving}
              >
                <option value="">Select a topology to load node groups...</option>
                {topologies.map((t) => (
                  <option key={t.metadata.name} value={t.metadata.name}>
                    {t.metadata.name} ({t.spec.nodeGroups?.length ?? 0} node groups)
                  </option>
                ))}
              </select>
              <span className="form-hint">
                Select a topology to populate node group options
              </span>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label className="form-label" htmlFor="source-group">
                  Source Node Group
                </label>
                {selectedTopology && nodeGroups.length > 0 ? (
                  <select
                    id="source-group"
                    className="form-select"
                    value={sourceGroup}
                    onChange={(e) => setSourceGroup(e.target.value)}
                    disabled={saving}
                  >
                    <option value="">Select source group...</option>
                    {nodeGroups.map((g) => (
                      <option key={g.name} value={g.name}>
                        {g.name} ({g.replicas} replicas)
                      </option>
                    ))}
                  </select>
                ) : (
                  <input
                    id="source-group"
                    type="text"
                    className="form-input"
                    placeholder="e.g., drones"
                    value={sourceGroup}
                    onChange={(e) => setSourceGroup(e.target.value)}
                    disabled={saving}
                  />
                )}
              </div>

              <div className="form-group">
                <label className="form-label" htmlFor="dest-group">
                  Destination Node Group
                </label>
                {selectedTopology && nodeGroups.length > 0 ? (
                  <select
                    id="dest-group"
                    className="form-select"
                    value={destGroup}
                    onChange={(e) => setDestGroup(e.target.value)}
                    disabled={saving}
                  >
                    <option value="">Select destination group...</option>
                    {nodeGroups.map((g) => (
                      <option key={g.name} value={g.name}>
                        {g.name} ({g.replicas} replicas)
                      </option>
                    ))}
                  </select>
                ) : (
                  <input
                    id="dest-group"
                    type="text"
                    className="form-input"
                    placeholder="e.g., ground-stations"
                    value={destGroup}
                    onChange={(e) => setDestGroup(e.target.value)}
                    disabled={saving}
                  />
                )}
              </div>
            </div>
          </section>

          {/* Policy Section */}
          <section className="form-section">
            <h2 className="form-section__title">Traffic Policy</h2>
            <div className="form-row">
              <div className="form-group">
                <label className="form-label" htmlFor="bandwidth">
                  Bandwidth
                </label>
                <input
                  id="bandwidth"
                  type="text"
                  className={`form-input${policyErrors.bandwidth ? ' form-input--error' : ''}`}
                  placeholder="10Mbps"
                  value={policy.bandwidth}
                  onChange={(e) => handlePolicyChange('bandwidth', e.target.value)}
                  disabled={saving}
                />
                {policyErrors.bandwidth ? (
                  <span className="form-hint form-hint--error">{policyErrors.bandwidth}</span>
                ) : (
                  <span className="form-hint">e.g., 10Mbps, 1Gbps</span>
                )}
              </div>

              <div className="form-group">
                <label className="form-label" htmlFor="latency">
                  Latency
                </label>
                <input
                  id="latency"
                  type="text"
                  className={`form-input${policyErrors.latency ? ' form-input--error' : ''}`}
                  placeholder="10ms"
                  value={policy.latency}
                  onChange={(e) => handlePolicyChange('latency', e.target.value)}
                  disabled={saving}
                />
                {policyErrors.latency ? (
                  <span className="form-hint form-hint--error">{policyErrors.latency}</span>
                ) : (
                  <span className="form-hint">e.g., 10ms, 100ms</span>
                )}
              </div>
            </div>

            <div className="form-row">
              <div className="form-group">
                <label className="form-label" htmlFor="jitter">
                  Jitter
                </label>
                <input
                  id="jitter"
                  type="text"
                  className={`form-input${policyErrors.jitter ? ' form-input--error' : ''}`}
                  placeholder="5ms"
                  value={policy.jitter}
                  onChange={(e) => handlePolicyChange('jitter', e.target.value)}
                  disabled={saving}
                />
                {policyErrors.jitter ? (
                  <span className="form-hint form-hint--error">{policyErrors.jitter}</span>
                ) : (
                  <span className="form-hint">e.g., 5ms, 20ms</span>
                )}
              </div>

              <div className="form-group">
                <label className="form-label" htmlFor="packet-loss">
                  Packet Loss
                </label>
                <input
                  id="packet-loss"
                  type="text"
                  className={`form-input${policyErrors.packetLoss ? ' form-input--error' : ''}`}
                  placeholder="0.1%"
                  value={policy.packetLoss}
                  onChange={(e) => handlePolicyChange('packetLoss', e.target.value)}
                  disabled={saving}
                />
                {policyErrors.packetLoss ? (
                  <span className="form-hint form-hint--error">{policyErrors.packetLoss}</span>
                ) : (
                  <span className="form-hint">e.g., 0.1%, 1%</span>
                )}
              </div>
            </div>
          </section>
        </div>

        {/* Preview Panel */}
        <div className="tc-edit__preview">
          <div className="preview-panel">
            <h3 className="preview-panel__title">YAML Preview</h3>
            <pre className="preview-panel__code">
              {`apiVersion: simulation.kuro.io/v1alpha1
kind: TrafficControl
metadata:
  name: ${name}
  namespace: ${namespace}
spec:
  source:
    matchLabels:
      kuro.io/node-group: ${sourceGroup || '<source>'}
  destination:
    matchLabels:
      kuro.io/node-group: ${destGroup || '<destination>'}
  policy:
    bandwidth: "${policy.bandwidth}"
    latency: "${policy.latency}"
    jitter: "${policy.jitter}"
    packetLoss: "${policy.packetLoss}"`}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}

export default TrafficControlEdit;
