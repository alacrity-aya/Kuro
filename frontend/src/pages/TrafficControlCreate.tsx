import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiClient } from '../api/client';
import { validatePolicy, type PolicyValidationResult } from '../utils/policyValidator';
import type { NetworkTopology, TrafficControl, NodeGroup } from '../types/api';
import './TrafficControlCreate.css';

interface TrafficControlCreateProps {
  onCreated?: (name: string, namespace: string) => void;
  onCancel?: () => void;
}

// Default policy values
const DEFAULT_POLICY = {
  bandwidth: '10Mbps',
  latency: '10ms',
  jitter: '5ms',
  packetLoss: '0.1%',
};

function TrafficControlCreate({ onCreated, onCancel }: TrafficControlCreateProps) {
  const navigate = useNavigate();

  // Form state
  const [name, setName] = useState('');
  const [namespace] = useState('kuro-experiment');
  const [selectedTopology, setSelectedTopology] = useState('');
  const [sourceGroup, setSourceGroup] = useState('');
  const [destGroup, setDestGroup] = useState('');
  const [policy, setPolicy] = useState(DEFAULT_POLICY);

  // Data state
  const [topologies, setTopologies] = useState<NetworkTopology[]>([]);
  const [nodeGroups, setNodeGroups] = useState<NodeGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [policyErrors, setPolicyErrors] = useState<Record<string, string>>({});

  const loadTopologies = useCallback(async () => {
    setLoading(true);
    setError(null);

    const response = await apiClient.listTopologies(namespace);

    if (response.success && response.data) {
      setTopologies(response.data.items);
    } else {
      setError(response.error || 'Failed to load topologies');
    }

    setLoading(false);
  }, [namespace]);

  // Load topologies on mount
  useEffect(() => {
    loadTopologies();
  }, [loadTopologies]);

  // Update node groups when topology changes
  useEffect(() => {
    if (selectedTopology) {
      const topology = topologies.find((t) => t.metadata.name === selectedTopology);
      if (topology?.spec?.nodeGroups) {
        setNodeGroups(topology.spec.nodeGroups);
        // Reset source and dest when topology changes
        setSourceGroup('');
        setDestGroup('');
      }
    } else {
      setNodeGroups([]);
      setSourceGroup('');
      setDestGroup('');
    }
  }, [selectedTopology, topologies]);

  // Handle policy field change
  const handlePolicyChange = (field: keyof typeof policy, value: string) => {
    setPolicy((prev) => ({ ...prev, [field]: value }));
    // Clear error for this field when user types
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
    if (!name.trim()) {
      return 'Name is required';
    }
    if (!/^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/.test(name)) {
      return 'Name must consist of lowercase alphanumeric characters or "-"';
    }
    if (!selectedTopology) {
      return 'Please select a topology';
    }
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

    setSubmitting(true);
    setError(null);

    // Build TrafficControl CRD
    const trafficControl: TrafficControl = {
      apiVersion: 'simulation.kuro.io/v1alpha1',
      kind: 'TrafficControl',
      metadata: {
        name: name.trim(),
        namespace,
        uid: '',
        creationTimestamp: '',
      },
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
      const response = await apiClient.createTrafficControl(trafficControl);

      if (response.success && response.data) {
        if (onCreated) {
          onCreated(name.trim(), namespace);
        } else {
          navigate('/traffic-controls');
        }
      } else {
        setError(response.error || 'Failed to create traffic control');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      console.error('Failed to create traffic control:', err);
    } finally {
      setSubmitting(false);
    }
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
      <div className="tc-create">
        <div className="tc-create__loading">
          <div className="tc-create__spinner" />
          <span>Loading topologies...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="tc-create">
      <header className="tc-create__header">
        <div className="tc-create__title-section">
          <h1 className="tc-create__title">Create Traffic Control</h1>
          <p className="tc-create__subtitle">
            Define network traffic shaping policies between node groups
          </p>
        </div>
        <div className="tc-create__header-actions">
          <button className="btn btn--secondary" onClick={handleCancel} disabled={submitting}>
            Cancel
          </button>
          <button
            className="btn btn--primary"
            onClick={handleSubmit}
            disabled={submitting}
          >
            {submitting ? 'Creating...' : 'Create Traffic Control'}
          </button>
        </div>
      </header>

      {error && (
        <div className="tc-create__error">
          <span className="tc-create__error-icon">⚠️</span>
          <span className="tc-create__error-message">{error}</span>
        </div>
      )}

      <div className="tc-create__content">
        <div className="tc-create__form">
          {/* Basic Info Section */}
          <section className="form-section">
            <h2 className="form-section__title">Basic Information</h2>
            <div className="form-group">
              <label className="form-label" htmlFor="name">
                Name <span className="form-label__required">*</span>
              </label>
              <input
                id="name"
                type="text"
                className="form-input"
                placeholder="my-traffic-control"
                value={name}
                onChange={(e) => setName(e.target.value)}
                disabled={submitting}
              />
              <span className="form-hint">
                Lowercase alphanumeric characters and '-' only
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
            <h2 className="form-section__title">Topology Selection</h2>
            <div className="form-group">
              <label className="form-label" htmlFor="topology">
                Topology <span className="form-label__required">*</span>
              </label>
              <select
                id="topology"
                className="form-select"
                value={selectedTopology}
                onChange={(e) => setSelectedTopology(e.target.value)}
                disabled={submitting}
              >
                <option value="">Select a topology...</option>
                {topologies.map((t) => (
                  <option key={t.metadata.name} value={t.metadata.name}>
                    {t.metadata.name} ({t.spec.nodeGroups?.length ?? 0} node groups)
                  </option>
                ))}
              </select>
              {topologies.length === 0 && (
                <span className="form-hint form-hint--warning">
                  No topologies found. Please create a topology first.
                </span>
              )}
            </div>

            <div className="form-row">
              <div className="form-group">
                <label className="form-label" htmlFor="source-group">
                  Source Node Group <span className="form-label__required">*</span>
                </label>
                <select
                  id="source-group"
                  className="form-select"
                  value={sourceGroup}
                  onChange={(e) => setSourceGroup(e.target.value)}
                  disabled={submitting || !selectedTopology}
                >
                  <option value="">Select source group...</option>
                  {nodeGroups.map((g) => (
                    <option key={g.name} value={g.name}>
                      {g.name} ({g.replicas} replicas)
                    </option>
                  ))}
                </select>
              </div>

              <div className="form-group">
                <label className="form-label" htmlFor="dest-group">
                  Destination Node Group <span className="form-label__required">*</span>
                </label>
                <select
                  id="dest-group"
                  className="form-select"
                  value={destGroup}
                  onChange={(e) => setDestGroup(e.target.value)}
                  disabled={submitting || !selectedTopology}
                >
                  <option value="">Select destination group...</option>
                  {nodeGroups.map((g) => (
                    <option key={g.name} value={g.name}>
                      {g.name} ({g.replicas} replicas)
                    </option>
                  ))}
                </select>
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
                  disabled={submitting}
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
                  disabled={submitting}
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
                  disabled={submitting}
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
                  disabled={submitting}
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
        <div className="tc-create__preview">
          <div className="preview-panel">
            <h3 className="preview-panel__title">YAML Preview</h3>
            <pre className="preview-panel__code">
              {`apiVersion: simulation.kuro.io/v1alpha1
kind: TrafficControl
metadata:
  name: ${name || '<name>'}
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

export default TrafficControlCreate;
