import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiClient } from '../api/client';
import type { TrafficControl, Phase } from '../types/api';
import './TrafficControlList.css';

interface TrafficControlListProps {
  onCreateTrafficControl?: () => void;
}

function TrafficControlList({ onCreateTrafficControl }: TrafficControlListProps) {
  const navigate = useNavigate();
  
  // State
  const [trafficControls, setTrafficControls] = useState<TrafficControl[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  // Filter state
  const [searchTerm, setSearchTerm] = useState('');
  const [filterPhase, setFilterPhase] = useState<string>('all');

  useEffect(() => {
    fetchTrafficControls();
  }, []);

  const fetchTrafficControls = async () => {
    setLoading(true);
    setError(null);
    
    const response = await apiClient.listTrafficControls('kuro-experiment');
    
    if (response.success && response.data) {
      setTrafficControls(response.data.items);
    } else {
      setError(response.error || 'Failed to load traffic controls');
    }
    
    setLoading(false);
  };

  // Filter traffic controls based on search and phase
  const filteredTrafficControls = trafficControls.filter((tc) => {
    const matchesSearch =
      tc.metadata.name.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesPhase = filterPhase === 'all' || tc.status?.phase === filterPhase;
    return matchesSearch && matchesPhase;
  });

  // Calculate statistics
  const phaseStats = trafficControls.reduce(
    (acc, tc) => {
      const phase = tc.status?.phase ?? 'Unknown';
      acc[phase] = (acc[phase] ?? 0) + 1;
      return acc;
    },
    {} as Record<string, number>
  );

  const handleCreateTrafficControl = () => {
    if (onCreateTrafficControl) {
      onCreateTrafficControl();
    } else {
      navigate('/traffic-controls/create');
    }
  };

  const handleDeleteTrafficControl = async (name: string) => {
    if (!window.confirm(`Are you sure you want to delete traffic control "${name}"?`)) {
      return;
    }
    
    const response = await apiClient.deleteTrafficControl(name, 'kuro-experiment');
    
    if (response.success) {
      fetchTrafficControls();
    } else {
      console.error('Failed to delete traffic control:', response.error);
      alert(`Failed to delete: ${response.error}`);
    }
  };

  const handleViewTrafficControl = (name: string) => {
    navigate(`/traffic-controls/kuro-experiment/${name}`);
  };

  // Format policy summary
  const formatPolicySummary = (policy: TrafficControl['spec']['policy']) => {
    const parts = [];
    if (policy.bandwidth) parts.push(policy.bandwidth);
    if (policy.latency) parts.push(`${policy.latency} latency`);
    if (policy.jitter) parts.push(`${policy.jitter} jitter`);
    if (policy.packetLoss && policy.packetLoss !== '0%') parts.push(`${policy.packetLoss} loss`);
    return parts.length > 0 ? parts.join(', ') : 'No policy set';
  };

  // Get phase badge class
  const getPhaseClass = (phase: Phase | undefined): string => {
    const p = (phase ?? 'Unknown').toLowerCase();
    return `tc-card__phase tc-card__phase--${p}`;
  };

  if (loading && trafficControls.length === 0) {
    return (
      <div className="tc-list">
        <div className="tc-list__loading">
          <div className="tc-list__spinner" />
          <span>Loading traffic controls...</span>
        </div>
      </div>
    );
  }

  if (error && trafficControls.length === 0) {
    return (
      <div className="tc-list">
        <div className="tc-list__error">
          <span>⚠️ {error}</span>
          <button className="btn btn--primary" onClick={() => fetchTrafficControls()}>
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="tc-list">
      <header className="tc-list__header">
        <div className="tc-list__title-section">
          <h1 className="tc-list__title">Traffic Controls</h1>
          <p className="tc-list__subtitle">
            Manage network traffic shaping policies between node groups
          </p>
        </div>
        <div className="tc-list__header-actions">
          <button className="btn btn--primary" onClick={handleCreateTrafficControl}>
            <span className="btn__icon">➕</span>
            Create Traffic Control
          </button>
        </div>
      </header>

      {/* Summary Bar */}
      <div className="tc-list__summary">
        <div className="summary-item">
          <span className="summary-item__label">Total</span>
          <span className="summary-item__value">{trafficControls.length}</span>
        </div>
        <div className="summary-item summary-item--running">
          <span className="summary-item__label">Running</span>
          <span className="summary-item__value">{phaseStats['Running'] ?? 0}</span>
        </div>
        <div className="summary-item summary-item--pending">
          <span className="summary-item__label">Pending</span>
          <span className="summary-item__value">{phaseStats['Pending'] ?? 0}</span>
        </div>
        <div className="summary-item summary-item--failed">
          <span className="summary-item__label">Failed</span>
          <span className="summary-item__value">{phaseStats['Failed'] ?? 0}</span>
        </div>
      </div>

      {/* Filters */}
      <div className="tc-list__filters">
        <div className="search-input">
          <span className="search-input__icon">🔍</span>
          <input
            type="text"
            placeholder="Search traffic controls..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
        <select
          className="filter-select"
          value={filterPhase}
          onChange={(e) => setFilterPhase(e.target.value)}
        >
          <option value="all">All Phases</option>
          <option value="Running">Running</option>
          <option value="Pending">Pending</option>
          <option value="Failed">Failed</option>
          <option value="Succeeded">Succeeded</option>
        </select>
      </div>

      {/* Traffic Controls Grid */}
      {filteredTrafficControls.length === 0 ? (
        <div className="tc-list__empty">
          <span className="tc-list__empty-icon">🎛️</span>
          <h3>No traffic controls found</h3>
          <p>
            {searchTerm || filterPhase !== 'all'
              ? 'Try adjusting your filters'
              : 'Create your first traffic control to define network policies'}
          </p>
          {!searchTerm && filterPhase === 'all' && (
            <button className="btn btn--primary" onClick={handleCreateTrafficControl}>
              Create Traffic Control
            </button>
          )}
        </div>
      ) : (
        <div className="tc-list__grid">
          {filteredTrafficControls.map((tc) => (
            <div key={tc.metadata.uid} className="tc-card">
              <div className="tc-card__header">
                <h3 className="tc-card__name">{tc.metadata.name}</h3>
                <span className={getPhaseClass(tc.status?.phase)}>
                  {tc.status?.phase ?? 'Unknown'}
                </span>
              </div>

              <div className="tc-card__body">
                {/* Source */}
                <div className="tc-card__section">
                  <span className="tc-card__section-label">Source</span>
                  <div className="tc-card__labels">
                    {Object.entries(tc.spec.source.matchLabels).map(([key, value]) => (
                      <span key={key} className="tc-card__label-tag tc-card__label-tag--source">
                        {key}={value}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Destination */}
                <div className="tc-card__section">
                  <span className="tc-card__section-label">Destination</span>
                  <div className="tc-card__labels">
                    {Object.entries(tc.spec.destination.matchLabels).map(([key, value]) => (
                      <span key={key} className="tc-card__label-tag tc-card__label-tag--dest">
                        {key}={value}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Policy Summary */}
                <div className="tc-card__policy">
                  <span className="tc-card__policy-icon">⚙️</span>
                  <span className="tc-card__policy-text">
                    {formatPolicySummary(tc.spec.policy)}
                  </span>
                </div>

                {/* Stats Row */}
                <div className="tc-card__stats">
                  <div className="tc-card__stat">
                    <span className="tc-card__stat-label">Applied Links</span>
                    <span className="tc-card__stat-value">{tc.status?.appliedLinks ?? 0}</span>
                  </div>
                  <div className="tc-card__stat">
                    <span className="tc-card__stat-label">Created</span>
                    <span className="tc-card__stat-value">
                      {new Date(tc.metadata.creationTimestamp).toLocaleDateString()}
                    </span>
                  </div>
                </div>
              </div>

              {/* Actions */}
              <div className="tc-card__actions">
                <button
                  className="btn btn--secondary"
                  onClick={() => handleViewTrafficControl(tc.metadata.name)}
                >
                  View
                </button>
                <button
                  className="btn btn--danger"
                  onClick={() => handleDeleteTrafficControl(tc.metadata.name)}
                >
                  Delete
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default TrafficControlList;
