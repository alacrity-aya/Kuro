import { useState, useEffect } from 'react';
import { useTopologyStore } from '../stores';
import './TopologyList.css';

interface TopologyListProps {
  onViewTopology?: (name: string, namespace: string) => void;
  onCreateTopology?: () => void;
}

function TopologyList({ onViewTopology, onCreateTopology }: TopologyListProps) {
  // Get state from store
  const topologies = useTopologyStore((state) => state.topologies);
  const loading = useTopologyStore((state) => state.loading);
  const error = useTopologyStore((state) => state.error);
  
  // Get actions from store
  const fetchTopologies = useTopologyStore((state) => state.fetchTopologies);
  
  // Local filter state
  const [searchTerm, setSearchTerm] = useState('');
  const [filterPhase, setFilterPhase] = useState<string>('all');

  useEffect(() => {
    fetchTopologies();
  }, [fetchTopologies]);

  // Filter topologies based on search and phase
  const filteredTopologies = topologies.filter((t) => {
    const matchesSearch =
      t.metadata.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      t.metadata.namespace.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesPhase = filterPhase === 'all' || t.status?.phase === filterPhase;
    return matchesSearch && matchesPhase;
  });

  // Calculate statistics
  const phaseStats = topologies.reduce(
    (acc, t) => {
      const phase = t.status?.phase ?? 'Unknown';
      acc[phase] = (acc[phase] ?? 0) + 1;
      return acc;
    },
    {} as Record<string, number>
  );

  const handleCreateTopology = () => {
    if (onCreateTopology) {
      onCreateTopology();
    }
  };

  const handleDeleteTopology = (name: string, namespace: string) => {
    console.log('Delete topology:', name, namespace);
    // TODO: Implement delete confirmation modal
  };

  const handleViewTopology = (name: string, namespace: string) => {
    console.log('View topology:', name, namespace);
    if (onViewTopology) {
      onViewTopology(name, namespace);
    }
  };

  if (loading && topologies.length === 0) {
    return (
      <div className="topology-list">
        <div className="topology-list__loading">
          <div className="topology-list__spinner" />
          <span>Loading topologies...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="topology-list">
        <div className="topology-list__error">
          <span>⚠️ {error}</span>
          <button className="btn btn--primary" onClick={() => fetchTopologies()}>
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="topology-list">
      <header className="topology-list__header">
        <div className="topology-list__title-section">
          <h1 className="topology-list__title">Topologies</h1>
          <p className="topology-list__subtitle">
            Manage your network simulation topologies
          </p>
        </div>
        <button className="btn btn--primary" onClick={handleCreateTopology}>
          <span className="btn__icon">➕</span>
          Create Topology
        </button>
      </header>

      {/* Summary Bar */}
      <div className="topology-list__summary">
        <div className="summary-item">
          <span className="summary-item__label">Total</span>
          <span className="summary-item__value">{topologies.length}</span>
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
      <div className="topology-list__filters">
        <div className="search-input">
          <span className="search-input__icon">🔍</span>
          <input
            type="text"
            placeholder="Search topologies..."
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

      {/* Topology Grid */}
      {filteredTopologies.length === 0 ? (
        <div className="topology-list__empty">
          <span className="topology-list__empty-icon">🌐</span>
          <h3>No topologies found</h3>
          <p>
            {searchTerm || filterPhase !== 'all'
              ? 'Try adjusting your filters'
              : 'Create your first topology to get started'}
          </p>
          {!searchTerm && filterPhase === 'all' && (
            <button className="btn btn--primary" onClick={handleCreateTopology}>
              Create Topology
            </button>
          )}
        </div>
      ) : (
        <div className="topology-list__grid">
          {filteredTopologies.map((topology) => (
            <div key={topology.metadata.uid} className="topology-card">
              <div className="topology-card__header">
                <h3 className="topology-card__name">{topology.metadata.name}</h3>
                <span
                  className={`topology-card__phase topology-card__phase--${(
                    topology.status?.phase ?? 'Unknown'
                  ).toLowerCase()}`}
                >
                  {topology.status?.phase ?? 'Unknown'}
                </span>
              </div>

              <div className="topology-card__body">
                <div className="topology-card__row">
                  <span className="topology-card__label">Namespace</span>
                  <span className="topology-card__value">{topology.metadata.namespace}</span>
                </div>
                <div className="topology-card__row">
                  <span className="topology-card__label">Node Groups</span>
                  <span className="topology-card__value">
                    {topology.spec.nodeGroups.length}
                  </span>
                </div>
                <div className="topology-card__row">
                  <span className="topology-card__label">Total Nodes</span>
                  <span className="topology-card__value">
                    {topology.status?.nodeCount ?? 0}
                  </span>
                </div>
                <div className="topology-card__row">
                  <span className="topology-card__label">Ready Nodes</span>
                  <span
                    className={`topology-card__value ${
                      (topology.status?.readyNodes ?? 0) === (topology.status?.nodeCount ?? 0)
                        ? 'topology-card__value--success'
                        : 'topology-card__value--warning'
                    }`}
                  >
                    {topology.status?.readyNodes ?? 0} / {topology.status?.nodeCount ?? 0}
                  </span>
                </div>
                <div className="topology-card__row">
                  <span className="topology-card__label">Created</span>
                  <span className="topology-card__value">
                    {new Date(topology.metadata.creationTimestamp).toLocaleDateString()}
                  </span>
                </div>
              </div>

              {/* Node Groups */}
              <div className="topology-card__groups">
                <span className="topology-card__groups-label">Groups:</span>
                <div className="topology-card__groups-list">
                  {topology.spec.nodeGroups.map((group) => (
                    <span key={group.name} className="topology-card__group-tag">
                      {group.name} ({group.replicas})
                    </span>
                  ))}
                </div>
              </div>

              {/* Actions */}
              <div className="topology-card__actions">
                <button
                  className="btn btn--secondary"
                  onClick={() =>
                    handleViewTopology(topology.metadata.name, topology.metadata.namespace)
                  }
                >
                  View
                </button>
                <button
                  className="btn btn--danger"
                  onClick={() =>
                    handleDeleteTopology(topology.metadata.name, topology.metadata.namespace)
                  }
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

export default TopologyList;