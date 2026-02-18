import { useEffect } from 'react';
import { useTopologyStore } from '../stores';
import './Dashboard.css';

interface DashboardProps {
  onViewTopology?: (name: string, namespace: string) => void;
}

interface StatsCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: string;
  trend?: 'up' | 'down' | 'neutral';
  trendValue?: string;
}

function StatsCard({ title, value, subtitle, icon, trend, trendValue }: StatsCardProps) {
  return (
    <div className="stats-card">
      <div className="stats-card__header">
        <span className="stats-card__icon">{icon}</span>
        <span className="stats-card__title">{title}</span>
      </div>
      <div className="stats-card__body">
        <span className="stats-card__value">{value}</span>
        {subtitle && <span className="stats-card__subtitle">{subtitle}</span>}
      </div>
      {trend && trendValue && (
        <div className={`stats-card__trend stats-card__trend--${trend}`}>
          <span>{trend === 'up' ? '↑' : trend === 'down' ? '↓' : '→'}</span>
          <span>{trendValue}</span>
        </div>
      )}
    </div>
  );
}

interface QuickActionButtonProps {
  icon: string;
  label: string;
  onClick: () => void;
}

function QuickActionButton({ icon, label, onClick }: QuickActionButtonProps) {
  return (
    <button className="quick-action-btn" onClick={onClick}>
      <span className="quick-action-btn__icon">{icon}</span>
      <span className="quick-action-btn__label">{label}</span>
    </button>
  );
}

function Dashboard({ onViewTopology }: DashboardProps) {
  // Get state from store
  const topologies = useTopologyStore((state) => state.topologies);
  const trafficControls = useTopologyStore((state) => state.trafficControls);
  const loading = useTopologyStore((state) => state.loading);
  const error = useTopologyStore((state) => state.error);
  
  // Get actions from store
  const fetchTopologies = useTopologyStore((state) => state.fetchTopologies);
  const fetchTrafficControls = useTopologyStore((state) => state.fetchTrafficControls);

  useEffect(() => {
    async function loadData() {
      await Promise.all([
        fetchTopologies(),
        fetchTrafficControls(),
      ]);
    }

    loadData();
  }, [fetchTopologies, fetchTrafficControls]);

  // Calculate statistics
  const totalNodes = topologies.reduce((sum, t) => sum + (t.status?.nodeCount ?? 0), 0);
  const readyNodes = topologies.reduce((sum, t) => sum + (t.status?.readyNodes ?? 0), 0);
  const runningTopologies = topologies.filter((t) => t.status?.phase === 'Running').length;
  const runningTCs = trafficControls.filter((tc) => tc.status?.phase === 'Running').length;

  // Group topologies by phase
  const topologyByPhase = topologies.reduce(
    (acc, t) => {
      const phase = t.status?.phase ?? 'Unknown';
      acc[phase] = (acc[phase] ?? 0) + 1;
      return acc;
    },
    {} as Record<string, number>
  );

  const handleCreateTopology = () => {
    console.log('Create topology clicked');
  };

  const handleCreateTrafficControl = () => {
    console.log('Create traffic control clicked');
  };

  const handleViewTopologies = () => {
    console.log('View topologies clicked');
  };

  const handleViewMetrics = () => {
    console.log('View metrics clicked');
  };

  const handleViewTopology = (name: string, namespace: string) => {
    if (onViewTopology) {
      onViewTopology(name, namespace);
    }
  };

  if (loading && topologies.length === 0) {
    return (
      <div className="dashboard">
        <div className="dashboard__loading">
          <div className="dashboard__spinner" />
          <span>Loading dashboard...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="dashboard">
        <div className="dashboard__error">
          <span>⚠️ {error}</span>
        </div>
      </div>
    );
  }

  return (
    <div className="dashboard">
      <header className="dashboard__header">
        <h1 className="dashboard__title">Dashboard</h1>
        <p className="dashboard__subtitle">Network simulation overview</p>
      </header>

      {/* Statistics Grid */}
      <section className="dashboard__stats">
        <StatsCard
          title="Total Nodes"
          value={totalNodes}
          subtitle={`${readyNodes} ready`}
          icon="📦"
          trend={readyNodes === totalNodes ? 'up' : 'neutral'}
          trendValue={`${readyNodes}/${totalNodes} ready`}
        />
        <StatsCard
          title="Topologies"
          value={topologies.length}
          subtitle={`${runningTopologies} running`}
          icon="🌐"
        />
        <StatsCard
          title="Traffic Controls"
          value={trafficControls.length}
          subtitle={`${runningTCs} active`}
          icon="🚦"
        />
        <StatsCard
          title="Simulation Health"
          value={runningTopologies === topologies.length && topologies.length > 0 ? '100%' : 'N/A'}
          subtitle="All systems operational"
          icon="✅"
        />
      </section>

      {/* Main Content */}
      <div className="dashboard__content">
        {/* Topology Status */}
        <section className="dashboard__section">
          <h2 className="section-title">Topology Status</h2>
          <div className="topology-status-grid">
            {topologies.length === 0 ? (
              <div className="empty-state">
                <span className="empty-state__icon">🌐</span>
                <p>No topologies found</p>
                <button className="btn btn--primary" onClick={handleCreateTopology}>
                  Create Topology
                </button>
              </div>
            ) : (
              topologies.map((topology) => (
                <div 
                  key={topology.metadata.uid} 
                  className="topology-card topology-card--clickable"
                  onClick={() => handleViewTopology(topology.metadata.name, topology.metadata.namespace)}
                >
                  <div className="topology-card__header">
                    <h3 className="topology-card__name">{topology.metadata.name}</h3>
                    <span className={`topology-card__phase topology-card__phase--${(topology.status?.phase ?? 'Unknown').toLowerCase()}`}>
                      {topology.status?.phase ?? 'Unknown'}
                    </span>
                  </div>
                  <div className="topology-card__body">
                    <div className="topology-card__stat">
                      <span className="topology-card__stat-label">Node Groups</span>
                      <span className="topology-card__stat-value">{topology.spec.nodeGroups.length}</span>
                    </div>
                    <div className="topology-card__stat">
                      <span className="topology-card__stat-label">Nodes</span>
                      <span className="topology-card__stat-value">
                        {topology.status?.readyNodes ?? 0}/{topology.status?.nodeCount ?? 0}
                      </span>
                    </div>
                    <div className="topology-card__stat">
                      <span className="topology-card__stat-label">Namespace</span>
                      <span className="topology-card__stat-value">{topology.metadata.namespace}</span>
                    </div>
                  </div>
                  <div className="topology-card__footer">
                    <span className="topology-card__time">
                      Created: {new Date(topology.metadata.creationTimestamp).toLocaleDateString()}
                    </span>
                    <span className="topology-card__action-hint">Click to view →</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </section>

        {/* Quick Actions */}
        <section className="dashboard__section">
          <h2 className="section-title">Quick Actions</h2>
          <div className="quick-actions">
            <QuickActionButton
              icon="➕"
              label="Create Topology"
              onClick={handleCreateTopology}
            />
            <QuickActionButton
              icon="🚦"
              label="Add Traffic Control"
              onClick={handleCreateTrafficControl}
            />
            <QuickActionButton
              icon="📋"
              label="View Topologies"
              onClick={handleViewTopologies}
            />
            <QuickActionButton
              icon="📊"
              label="View Metrics"
              onClick={handleViewMetrics}
            />
          </div>
        </section>

        {/* Phase Summary */}
        <section className="dashboard__section">
          <h2 className="section-title">Simulation Overview</h2>
          <div className="phase-summary">
            <div className="phase-item">
              <span className="phase-item__dot phase-item__dot--running" />
              <span className="phase-item__label">Running</span>
              <span className="phase-item__count">{topologyByPhase['Running'] ?? 0}</span>
            </div>
            <div className="phase-item">
              <span className="phase-item__dot phase-item__dot--pending" />
              <span className="phase-item__label">Pending</span>
              <span className="phase-item__count">{topologyByPhase['Pending'] ?? 0}</span>
            </div>
            <div className="phase-item">
              <span className="phase-item__dot phase-item__dot--failed" />
              <span className="phase-item__label">Failed</span>
              <span className="phase-item__count">{topologyByPhase['Failed'] ?? 0}</span>
            </div>
            <div className="phase-item">
              <span className="phase-item__dot phase-item__dot--succeeded" />
              <span className="phase-item__label">Succeeded</span>
              <span className="phase-item__count">{topologyByPhase['Succeeded'] ?? 0}</span>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}

export default Dashboard;