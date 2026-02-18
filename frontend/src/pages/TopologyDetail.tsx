import { useEffect, useCallback, useRef } from 'react';
import { ReactFlowProvider, useReactFlow } from 'reactflow';
import { TopologyCanvas } from '../components/topology';
import { TrafficControlPanel } from '../components';
import { useTopologyStore, useTopologyStats, useLocalView } from '../stores';
import type { TrafficPolicy, TopologyLink } from '../types/api';
import './TopologyDetail.css';

// ============================================================================
// Types
// ============================================================================

interface TopologyDetailProps {
  topologyName: string;
  namespace?: string;
  onBack?: () => void;
}

// ============================================================================
// Zoom Controls Component
// ============================================================================

function ZoomControls() {
  const { zoomIn, zoomOut, fitView } = useReactFlow();

  return (
    <div className="zoom-controls">
      <button 
        className="zoom-controls__btn" 
        onClick={() => zoomIn()} 
        title="Zoom In"
      >
        +
      </button>
      <button 
        className="zoom-controls__btn" 
        onClick={() => zoomOut()} 
        title="Zoom Out"
      >
        −
      </button>
      <button 
        className="zoom-controls__btn zoom-controls__btn--fit" 
        onClick={() => fitView({ padding: 0.2 })} 
        title="Fit to Screen"
      >
        ⊡
      </button>
    </div>
  );
}

// ============================================================================
// Node Detail Panel
// ============================================================================

function NodeDetailPanel() {
  const selectedNode = useTopologyStore((state) => state.selectedNode);
  const clearSelection = useTopologyStore((state) => state.clearSelection);
  const enterLocalView = useTopologyStore((state) => state.enterLocalView);
  const localViewNodeId = useTopologyStore((state) => state.localViewNodeId);

  if (!selectedNode) return null;

  const statusClass = `detail-panel__status detail-panel__status--${selectedNode.status}`;
  const isInLocalView = localViewNodeId === selectedNode.id;

  const handleEnterLocalView = () => {
    enterLocalView(selectedNode.id);
    clearSelection();
  };

  return (
    <div className="detail-panel">
      <div className="detail-panel__header">
        <h3 className="detail-panel__title">Node Details</h3>
        <button className="detail-panel__close" onClick={clearSelection}>×</button>
      </div>
      <div className="detail-panel__body">
        <div className="detail-field">
          <span className="detail-field__label">Name</span>
          <span className="detail-field__value">{selectedNode.name}</span>
        </div>
        <div className="detail-field">
          <span className="detail-field__label">ID</span>
          <span className="detail-field__value detail-field__value--mono">{selectedNode.id}</span>
        </div>
        <div className="detail-field">
          <span className="detail-field__label">IP Address</span>
          <span className="detail-field__value detail-field__value--mono">{selectedNode.ip}</span>
        </div>
        <div className="detail-field">
          <span className="detail-field__label">Role</span>
          <span className="detail-field__value">
            <span className="role-badge">{selectedNode.role}</span>
          </span>
        </div>
        <div className="detail-field">
          <span className="detail-field__label">Status</span>
          <span className={statusClass}>{selectedNode.status}</span>
        </div>
        <div className="detail-field">
          <span className="detail-field__label">Group</span>
          <span className="detail-field__value">{selectedNode.groupId}</span>
        </div>
        <div className="detail-field">
          <span className="detail-field__label">Labels</span>
          <div className="detail-field__labels">
            {Object.entries(selectedNode.labels).map(([key, value]) => (
              <span key={key} className="label-tag">
                {key}={value}
              </span>
            ))}
          </div>
        </div>
        
        {/* Local View Button */}
        {!isInLocalView && (
          <div className="detail-section-title">Actions</div>
        )}
        {!isInLocalView && (
          <button 
            className="btn btn--primary local-view-btn"
            onClick={handleEnterLocalView}
          >
            🔍 Enter Local View
          </button>
        )}
        {isInLocalView && (
          <div className="local-view-indicator">
            Currently viewing this node's local view
          </div>
        )}
      </div>
    </div>
  );
}

// ============================================================================
// Link Detail Panel
// ============================================================================

function LinkDetailPanel() {
  const selectedLink = useTopologyStore((state) => state.selectedLink);
  const clearSelection = useTopologyStore((state) => state.clearSelection);

  if (!selectedLink) return null;

  const metrics = selectedLink.metrics ?? null;

  return (
    <div className="detail-panel">
      <div className="detail-panel__header">
        <h3 className="detail-panel__title">Link Details</h3>
        <button className="detail-panel__close" onClick={clearSelection}>×</button>
      </div>
      <div className="detail-panel__body">
        <div className="detail-field">
          <span className="detail-field__label">Source</span>
          <span className="detail-field__value detail-field__value--mono">{selectedLink.sourceId}</span>
        </div>
        <div className="detail-field">
          <span className="detail-field__label">Target</span>
          <span className="detail-field__value detail-field__value--mono">{selectedLink.targetId}</span>
        </div>
        <div className="detail-field">
          <span className="detail-field__label">Status</span>
          <span className={`detail-panel__status detail-panel__status--${selectedLink.status}`}>
            {selectedLink.status}
          </span>
        </div>

        {selectedLink.policy && (
          <>
            <div className="detail-section-title">Traffic Policy</div>
            <div className="detail-field">
              <span className="detail-field__label">Bandwidth</span>
              <span className="detail-field__value">{selectedLink.policy.bandwidth}</span>
            </div>
            <div className="detail-field">
              <span className="detail-field__label">Latency</span>
              <span className="detail-field__value">{selectedLink.policy.latency}</span>
            </div>
            <div className="detail-field">
              <span className="detail-field__label">Jitter</span>
              <span className="detail-field__value">{selectedLink.policy.jitter}</span>
            </div>
            <div className="detail-field">
              <span className="detail-field__label">Packet Loss</span>
              <span className="detail-field__value">{selectedLink.policy.packetLoss}</span>
            </div>
          </>
        )}

        {metrics && (
          <>
            <div className="detail-section-title">Real-time Metrics</div>
            <div className="detail-field">
              <span className="detail-field__label">Bandwidth Usage</span>
              <span className="detail-field__value">{metrics.bandwidthUsage.toFixed(1)}%</span>
            </div>
            <div className="detail-field">
              <span className="detail-field__label">Current Latency</span>
              <span className="detail-field__value">{metrics.currentLatency.toFixed(1)} ms</span>
            </div>
            <div className="detail-field">
              <span className="detail-field__label">Current Jitter</span>
              <span className="detail-field__value">{metrics.currentJitter.toFixed(1)} ms</span>
            </div>
            <div className="detail-field">
              <span className="detail-field__label">Packet Loss Rate</span>
              <span className="detail-field__value">{metrics.packetLossRate.toFixed(2)}%</span>
            </div>
            <div className="detail-field">
              <span className="detail-field__label">Throughput</span>
              <span className="detail-field__value">{(metrics.bytesPerSecond / 1024).toFixed(1)} KB/s</span>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

// ============================================================================
// Main Topology Detail Component
// ============================================================================

function TopologyDetailInner({ topologyName, namespace = 'default', onBack }: TopologyDetailProps) {
  const canvasRef = useRef<HTMLDivElement>(null);
  
  // Get state from store
  const topology = useTopologyStore((state) => state.currentTopology);
  const nodes = useTopologyStore((state) => state.nodes);
  const trafficControls = useTopologyStore((state) => state.trafficControls);
  const loading = useTopologyStore((state) => state.loading);
  const error = useTopologyStore((state) => state.error);
  const selectedNode = useTopologyStore((state) => state.selectedNode);
  const selectedLink = useTopologyStore((state) => state.selectedLink);
  const sidebarCollapsed = useTopologyStore((state) => state.sidebarCollapsed);
  
  // Get actions from store
  const fetchTopology = useTopologyStore((state) => state.fetchTopology);
  const fetchTopologyNodes = useTopologyStore((state) => state.fetchTopologyNodes);
  const fetchTopologyLinks = useTopologyStore((state) => state.fetchTopologyLinks);
  const fetchTrafficControls = useTopologyStore((state) => state.fetchTrafficControls);
  const selectNode = useTopologyStore((state) => state.selectNode);
  const selectLink = useTopologyStore((state) => state.selectLink);
  const clearSelection = useTopologyStore((state) => state.clearSelection);
  const setSidebarCollapsed = useTopologyStore((state) => state.setSidebarCollapsed);
  const updateLinkPolicy = useTopologyStore((state) => state.updateLinkPolicy);
  const exitLocalView = useTopologyStore((state) => state.exitLocalView);
  
  // Get local view filtered data
  const { 
    nodes: displayNodes, 
    links: displayLinks, 
    isInLocalView, 
    localViewNode 
  } = useLocalView();
  
  // Get computed stats (use original nodes for total stats)
  const stats = useTopologyStats();

  // Load topology data
  useEffect(() => {
    async function loadTopologyData() {
      await Promise.all([
        fetchTopology(topologyName, namespace),
        fetchTopologyNodes(topologyName, namespace),
        fetchTopologyLinks(topologyName, namespace),
        fetchTrafficControls(namespace),
      ]);
    }

    loadTopologyData();
  }, [topologyName, namespace, fetchTopology, fetchTopologyNodes, fetchTopologyLinks, fetchTrafficControls]);

  // Handle node click
  const handleNodeClick = useCallback((node: typeof nodes[0]) => {
    selectNode(node);
  }, [selectNode]);

  // Handle edge click
  const handleEdgeClick = useCallback((link: TopologyLink) => {
    selectLink(link);
  }, [selectLink]);

  // Handle selection change (deselect)
  const handleSelectionChange = useCallback((nodeIds: string[], edgeIds: string[]) => {
    if (nodeIds.length === 0 && edgeIds.length === 0) {
      clearSelection();
    }
  }, [clearSelection]);

  // Handle traffic policy save
  const handlePolicySave = useCallback((linkId: string, policy: TrafficPolicy) => {
    updateLinkPolicy(linkId, policy);
    console.log(`Policy saved for link ${linkId}:`, policy);
  }, [updateLinkPolicy]);

  // Handle traffic policy reset
  const handlePolicyReset = useCallback((linkId: string) => {
    console.log(`Policy reset for link ${linkId}`);
  }, []);

  if (loading) {
    return (
      <div className="topology-detail">
        <div className="topology-detail__loading">
          <div className="topology-detail__spinner" />
          <span>Loading topology...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="topology-detail">
        <div className="topology-detail__error">
          <span className="topology-detail__error-icon">⚠️</span>
          <span>{error}</span>
          {onBack && (
            <button className="btn btn--secondary" onClick={onBack}>
              ← Back to List
            </button>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="topology-detail">
      {/* Header */}
      <header className="topology-detail__header">
        <div className="topology-detail__header-left">
          {onBack && (
            <button className="back-btn" onClick={onBack}>
              ← Back
            </button>
          )}
          <div className="topology-detail__title-group">
            <h1 className="topology-detail__title">{topology?.metadata.name ?? topologyName}</h1>
            <span className={`topology-detail__phase topology-detail__phase--${(topology?.status?.phase ?? 'Unknown').toLowerCase()}`}>
              {topology?.status?.phase ?? 'Unknown'}
            </span>
          </div>
        </div>
        <div className="topology-detail__header-right">
          <div className="topology-detail__stats">
            <div className="stat-item">
              <span className="stat-item__value">{stats.totalNodes}</span>
              <span className="stat-item__label">Nodes</span>
            </div>
            <div className="stat-item">
              <span className="stat-item__value">{stats.runningNodes}</span>
              <span className="stat-item__label">Running</span>
            </div>
            <div className="stat-item">
              <span className="stat-item__value">{stats.totalLinks}</span>
              <span className="stat-item__label">Links</span>
            </div>
            <div className="stat-item">
              <span className="stat-item__value">{stats.activeLinks}</span>
              <span className="stat-item__label">Active</span>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="topology-detail__body">
        {/* Sidebar - Traffic Controls */}
        <aside className={`topology-detail__sidebar ${sidebarCollapsed ? 'topology-detail__sidebar--collapsed' : ''}`}>
          <div className="sidebar-header">
            <h3>Traffic Controls</h3>
            <button 
              className="sidebar-toggle"
              onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
            >
              {sidebarCollapsed ? '»' : '«'}
            </button>
          </div>
          {!sidebarCollapsed && (
            <div className="sidebar-content">
              {trafficControls.length === 0 ? (
                <div className="sidebar-empty">
                  <span>No traffic controls</span>
                </div>
              ) : (
                <div className="tc-list">
                  {trafficControls.map((tc) => (
                    <div key={tc.metadata.uid} className="tc-item">
                      <div className="tc-item__name">{tc.metadata.name}</div>
                      <div className="tc-item__policy">
                        {tc.spec.policy.bandwidth} | {tc.spec.policy.latency}
                      </div>
                      <span className={`tc-item__phase tc-item__phase--${(tc.status?.phase ?? 'Unknown').toLowerCase()}`}>
                        {tc.status?.phase ?? 'Unknown'}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </aside>

        {/* Canvas Area */}
        <div className="topology-detail__canvas" ref={canvasRef}>
          {isInLocalView && localViewNode && (
            <div className="local-view-banner">
              <span className="local-view-banner__text">
                🔍 Local View: <strong>{localViewNode.name}</strong> ({localViewNode.ip})
              </span>
              <button className="local-view-banner__exit" onClick={exitLocalView}>
                Exit Local View
              </button>
            </div>
          )}
          <TopologyCanvas
            nodes={displayNodes}
            links={displayLinks}
            selectedNodeId={selectedNode?.id}
            selectedLinkId={selectedLink?.id}
            onNodeClick={handleNodeClick}
            onEdgeClick={handleEdgeClick}
            onSelectionChange={handleSelectionChange}
            fitView
            showMiniMap
          />
          <ZoomControls />
        </div>

        {/* Detail Panels */}
        {selectedNode && <NodeDetailPanel />}
        {selectedLink && (
          <div className="topology-detail__panels">
            <LinkDetailPanel />
            <TrafficControlPanel
              link={selectedLink}
              onSave={handlePolicySave}
              onReset={handlePolicyReset}
              onClose={clearSelection}
            />
          </div>
        )}
      </div>
    </div>
  );
}

// ============================================================================
// Export with ReactFlow Provider
// ============================================================================

function TopologyDetail(props: TopologyDetailProps) {
  return (
    <ReactFlowProvider>
      <TopologyDetailInner {...props} />
    </ReactFlowProvider>
  );
}

export default TopologyDetail;