import { useCallback, useRef, useMemo } from 'react';
import { ReactFlowProvider, useReactFlow } from 'reactflow';
import { TopologyCanvas, TrafficControlFilter } from '../components/topology';
import { TrafficControlPanel } from '../components';
import {
  useTopologyStore,
  useTopologyStats,
  useLocalView,
  useTopologyData,
  useTopologySelection,
  useTopologyUI,
  useTopologyActions,
  useNodeActions,
  useLinkActions,
  useTrafficControlFilter,
} from '../stores';
import { useAutoRefresh } from '../hooks/useAutoRefresh';
import { getTrafficControlColor } from '../utils/colorPalette';
import type { TrafficPolicy, TopologyLink, TrafficControl } from '../types/api';
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

interface NodeDetailPanelProps {
  namespace?: string;
  topologyName?: string;
  trafficControls?: TrafficControl[];
}

function NodeDetailPanel({ namespace, topologyName, trafficControls }: NodeDetailPanelProps) {
  const { selectedNode } = useTopologySelection();
  const { clearSelection, enterLocalView } = useNodeActions();
  const localViewNodeId = useTopologyStore((state) => state.localViewNodeId);

  // Compute related TrafficControls where this node is source or destination
  const relatedTrafficControls = useMemo(() => {
    if (!selectedNode || !trafficControls) return [];
    
    const nodeRole = selectedNode.labels?.role;
    if (!nodeRole) return [];
    
    return trafficControls.filter(tc => {
      const sourceRole = tc.spec.source.matchLabels['role'];
      const destRole = tc.spec.destination.matchLabels['role'];
      return sourceRole === nodeRole || destRole === nodeRole;
    });
  }, [selectedNode, trafficControls]);

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
        
        {/* Context Information */}
        {namespace && (
          <div className="detail-field">
            <span className="detail-field__label">Namespace</span>
            <span className="detail-field__value">{namespace}</span>
          </div>
        )}
        {topologyName && (
          <div className="detail-field">
            <span className="detail-field__label">Topology</span>
            <span className="detail-field__value">{topologyName}</span>
          </div>
        )}
        
        {/* Related Traffic Controls */}
        {relatedTrafficControls.length > 0 && (
          <div className="detail-field">
            <span className="detail-field__label">Traffic Controls</span>
            <div className="detail-field__tc-list">
              {relatedTrafficControls.map(tc => (
                <span key={tc.metadata.uid} className="detail-field__tc-tag">
                  {tc.metadata.name}
                </span>
              ))}
            </div>
          </div>
        )}
        
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
  const { selectedLink } = useTopologySelection();
  const { clearSelection } = useLinkActions();

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
  
  // Get state from store - using batch selectors for better performance
  const { 
    topology, 
    nodes, 
    links, 
    trafficControls, 
    loading, 
    error 
  } = useTopologyData();
  
  const { 
    selectedNode, 
    selectedLink 
  } = useTopologySelection();
  
  const { 
    detailSidebarCollapsed
  } = useTopologyUI();
  
  // Get Actions from store - stable references
  const actions = useTopologyActions();
  
  // Get local view filtered data
  const { 
    nodes: displayNodes, 
    links: displayLinks, 
    isInLocalView, 
    localViewNode 
  } = useLocalView();
  
  // Get computed stats (use original nodes for total stats)
  const stats = useTopologyStats();

  // TC Filter state
  const {
    trafficControls: tcList,
    selectedTrafficControlIds,
    toggleTrafficControlSelection,
    clearTrafficControlSelection,
  } = useTrafficControlFilter();

  // Compute which links are highlighted and their colors
  const trafficControlColors = useMemo(() => {
    const colorMap = new Map<string, string>();
    if (selectedTrafficControlIds.length === 0) return colorMap;

    tcList.forEach((tc, index) => {
      if (!selectedTrafficControlIds.includes(tc.metadata.uid)) return;

      const color = getTrafficControlColor(index);
      // Find links matching this TC's source/destination labels
      const sourceRole = tc.spec.source.matchLabels['role'];
      const destRole = tc.spec.destination.matchLabels['role'];

      links.forEach(link => {
        const sourceNode = nodes.find(n => n.id === link.sourceId);
        const targetNode = nodes.find(n => n.id === link.targetId);
        if (sourceNode?.labels?.role === sourceRole && targetNode?.labels?.role === destRole) {
          colorMap.set(link.id, color);
        }
      });
    });
    return colorMap;
  }, [tcList, selectedTrafficControlIds, links, nodes]);

  const highlightedLinkIds = useMemo(() => {
    return new Set(trafficControlColors.keys());
  }, [trafficControlColors]);

  // Refresh function for auto-refresh
  const refreshData = useCallback(async () => {
    await Promise.all([
      actions.fetchTopology(topologyName, namespace),
      actions.fetchTopologyNodes(topologyName, namespace),
      actions.fetchTopologyLinks(topologyName, namespace),
      actions.fetchTrafficControls(namespace),
    ]);
  }, [actions, topologyName, namespace]);

  // Auto-refresh every 5 seconds
  const { isRefreshing } = useAutoRefresh({
    onRefresh: refreshData,
    initialInterval: 5000,
    initialEnabled: true,
  });

  // Handle node click
  const handleNodeClick = useCallback((node: typeof nodes[0]) => {
    actions.selectNode(node);
  }, [actions]);

  // Handle edge click
  const handleEdgeClick = useCallback((link: TopologyLink) => {
    actions.selectLink(link);
  }, [actions]);

  // Handle selection change - only for edge selection via canvas interaction
  // Note: We don't clear selection here to avoid flickering when clicking nodes
  // Selection is cleared via close button or clicking on canvas background
  const handleSelectionChange = useCallback((_nodeIds: string[], edgeIds: string[]) => {
    // Only handle edge selection (node selection is handled by handleNodeClick)
    if (edgeIds.length > 0) {
      const edgeId = edgeIds[0];
      const link = links.find(l => l.id === edgeId);
      if (link) {
        actions.selectLink(link);
      }
    }
  }, [actions, links]);

  // Handle traffic policy save
  const handlePolicySave = useCallback((linkId: string, policy: TrafficPolicy) => {
    actions.updateLinkPolicy(linkId, policy);
    console.log(`Policy saved for link ${linkId}:`, policy);
  }, [actions]);

  // Handle traffic policy reset
  const handlePolicyReset = useCallback((linkId: string) => {
    console.log(`Policy reset for link ${linkId}`);
  }, []);

  if (loading && nodes.length === 0) {
    return (
      <div className="topology-detail">
        <div className="topology-detail__loading">
          <div className="topology-detail__spinner" />
          <span>Loading topology...</span>
        </div>
      </div>
    );
  }

  if (error && !topology) {
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
          {isRefreshing && (
            <span className="topology-detail__refreshing" title="Refreshing...">
              🔄
            </span>
          )}
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
        {/* Sidebar - Traffic Controls & TSN */}
        <aside className={`topology-detail__sidebar ${detailSidebarCollapsed ? 'topology-detail__sidebar--collapsed' : ''}`}>
          <div className="sidebar-header">
            <h3>Traffic Controls</h3>
            <button 
              className="sidebar-toggle"
              onClick={() => actions.setDetailSidebarCollapsed(!detailSidebarCollapsed)}
            >
              {detailSidebarCollapsed ? '»' : '«'}
            </button>
          </div>
          {!detailSidebarCollapsed && (
            <div className="sidebar-content">
              {/* Traffic Controls Filter */}
              <div className="sidebar-section">
                <h4 className="sidebar-section-title">Filter by Traffic Control</h4>
                <TrafficControlFilter
                  trafficControls={trafficControls}
                  selectedIds={selectedTrafficControlIds}
                  onToggle={toggleTrafficControlSelection}
                  onClear={clearTrafficControlSelection}
                />
              </div>
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
              <button className="local-view-banner__exit" onClick={actions.exitLocalView}>
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
            onPaneClick={actions.clearSelection}
            onSelectionChange={handleSelectionChange}
            fitView
            showMiniMap
            topologyId={`${namespace}-${topologyName}`}
            trafficControlColors={trafficControlColors}
            highlightedLinkIds={highlightedLinkIds}
          />
          <ZoomControls />
        </div>

        {/* Detail Panels */}
        {selectedNode && (
          <NodeDetailPanel
            namespace={namespace}
            topologyName={topologyName}
            trafficControls={trafficControls}
          />
        )}
        {selectedLink && (
          <div className="topology-detail__panels">
            <LinkDetailPanel />
            <TrafficControlPanel
              link={selectedLink}
              onSave={handlePolicySave}
              onReset={handlePolicyReset}
              onClose={actions.clearSelection}
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