import { useState, useEffect, useCallback, useRef } from 'react';
import { ReactFlowProvider, useReactFlow } from 'reactflow';
import { TopologyCanvas } from '../components/topology';
import { TrafficControlPanel } from '../components';
import { apiClient } from '../api/client';
import type { 
  NetworkTopology, 
  TopologyNode, 
  TopologyLink, 
  TrafficControl,
  TrafficPolicy,
  LinkMetrics 
} from '../types/api';
import './TopologyDetail.css';

// ============================================================================
// Types
// ============================================================================

interface TopologyDetailProps {
  topologyName: string;
  namespace?: string;
  onBack?: () => void;
}

interface NodeDetailPanelProps {
  node: TopologyNode | null;
  onClose: () => void;
}

interface LinkDetailPanelProps {
  link: TopologyLink | null;
  onClose: () => void;
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

function NodeDetailPanel({ node, onClose }: NodeDetailPanelProps) {
  if (!node) return null;

  const statusClass = `detail-panel__status detail-panel__status--${node.status}`;

  return (
    <div className="detail-panel">
      <div className="detail-panel__header">
        <h3 className="detail-panel__title">Node Details</h3>
        <button className="detail-panel__close" onClick={onClose}>×</button>
      </div>
      <div className="detail-panel__body">
        <div className="detail-field">
          <span className="detail-field__label">Name</span>
          <span className="detail-field__value">{node.name}</span>
        </div>
        <div className="detail-field">
          <span className="detail-field__label">ID</span>
          <span className="detail-field__value detail-field__value--mono">{node.id}</span>
        </div>
        <div className="detail-field">
          <span className="detail-field__label">IP Address</span>
          <span className="detail-field__value detail-field__value--mono">{node.ip}</span>
        </div>
        <div className="detail-field">
          <span className="detail-field__label">Role</span>
          <span className="detail-field__value">
            <span className="role-badge">{node.role}</span>
          </span>
        </div>
        <div className="detail-field">
          <span className="detail-field__label">Status</span>
          <span className={statusClass}>{node.status}</span>
        </div>
        <div className="detail-field">
          <span className="detail-field__label">Group</span>
          <span className="detail-field__value">{node.groupId}</span>
        </div>
        <div className="detail-field">
          <span className="detail-field__label">Labels</span>
          <div className="detail-field__labels">
            {Object.entries(node.labels).map(([key, value]) => (
              <span key={key} className="label-tag">
                {key}={value}
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// Link Detail Panel
// ============================================================================

function LinkDetailPanel({ link, onClose }: LinkDetailPanelProps) {
  const [metrics, setMetrics] = useState<LinkMetrics | null>(null);

  useEffect(() => {
    if (link) {
      // Simulate loading metrics
      setMetrics(link.metrics ?? null);
    }
  }, [link]);

  if (!link) return null;

  return (
    <div className="detail-panel">
      <div className="detail-panel__header">
        <h3 className="detail-panel__title">Link Details</h3>
        <button className="detail-panel__close" onClick={onClose}>×</button>
      </div>
      <div className="detail-panel__body">
        <div className="detail-field">
          <span className="detail-field__label">Source</span>
          <span className="detail-field__value detail-field__value--mono">{link.sourceId}</span>
        </div>
        <div className="detail-field">
          <span className="detail-field__label">Target</span>
          <span className="detail-field__value detail-field__value--mono">{link.targetId}</span>
        </div>
        <div className="detail-field">
          <span className="detail-field__label">Status</span>
          <span className={`detail-panel__status detail-panel__status--${link.status}`}>
            {link.status}
          </span>
        </div>

        {link.policy && (
          <>
            <div className="detail-section-title">Traffic Policy</div>
            <div className="detail-field">
              <span className="detail-field__label">Bandwidth</span>
              <span className="detail-field__value">{link.policy.bandwidth}</span>
            </div>
            <div className="detail-field">
              <span className="detail-field__label">Latency</span>
              <span className="detail-field__value">{link.policy.latency}</span>
            </div>
            <div className="detail-field">
              <span className="detail-field__label">Jitter</span>
              <span className="detail-field__value">{link.policy.jitter}</span>
            </div>
            <div className="detail-field">
              <span className="detail-field__label">Packet Loss</span>
              <span className="detail-field__value">{link.policy.packetLoss}</span>
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
  const [topology, setTopology] = useState<NetworkTopology | null>(null);
  const [nodes, setNodes] = useState<TopologyNode[]>([]);
  const [links, setLinks] = useState<TopologyLink[]>([]);
  const [trafficControls, setTrafficControls] = useState<TrafficControl[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<TopologyNode | null>(null);
  const [selectedLink, setSelectedLink] = useState<TopologyLink | null>(null);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  
  const canvasRef = useRef<HTMLDivElement>(null);

  // Load topology data
  useEffect(() => {
    async function loadTopologyData() {
      try {
        setLoading(true);
        setError(null);

        const [topologyRes, nodesRes, linksRes, tcRes] = await Promise.all([
          apiClient.getTopology(topologyName, namespace),
          apiClient.getTopologyNodes(topologyName, namespace),
          apiClient.getTopologyLinks(topologyName, namespace),
          apiClient.listTrafficControls(namespace),
        ]);

        if (!topologyRes.success || !topologyRes.data) {
          throw new Error(topologyRes.error ?? 'Topology not found');
        }

        setTopology(topologyRes.data);
        if (nodesRes.success && nodesRes.data) {
          setNodes(nodesRes.data);
        }
        if (linksRes.success && linksRes.data) {
          setLinks(linksRes.data);
        }
        if (tcRes.success && tcRes.data) {
          setTrafficControls(tcRes.data.items);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load topology');
        console.error('Failed to load topology:', err);
      } finally {
        setLoading(false);
      }
    }

    loadTopologyData();
  }, [topologyName, namespace]);

  // Handle node click
  const handleNodeClick = useCallback((node: TopologyNode) => {
    setSelectedNode(node);
    setSelectedLink(null);
  }, []);

  // Handle edge click
  const handleEdgeClick = useCallback((link: TopologyLink) => {
    setSelectedLink(link);
    setSelectedNode(null);
  }, []);

  // Handle selection change (deselect)
  const handleSelectionChange = useCallback((nodeIds: string[], edgeIds: string[]) => {
    if (nodeIds.length === 0 && edgeIds.length === 0) {
      setSelectedNode(null);
      setSelectedLink(null);
    }
  }, []);

  // Close detail panels
  const handleCloseNodePanel = useCallback(() => setSelectedNode(null), []);
  const handleCloseLinkPanel = useCallback(() => setSelectedLink(null), []);

  // Handle traffic policy save
  const handlePolicySave = useCallback((linkId: string, policy: TrafficPolicy) => {
    // Update the link policy in local state (mock implementation)
    setLinks(prevLinks => 
      prevLinks.map(link => 
        link.id === linkId 
          ? { ...link, policy } 
          : link
      )
    );
    console.log(`Policy saved for link ${linkId}:`, policy);
  }, []);

  // Handle traffic policy reset
  const handlePolicyReset = useCallback((linkId: string) => {
    console.log(`Policy reset for link ${linkId}`);
  }, []);

  // Calculate summary stats
  const runningNodes = nodes.filter(n => n.status === 'running').length;
  const activeLinks = links.filter(l => l.status === 'active').length;

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
              <span className="stat-item__value">{nodes.length}</span>
              <span className="stat-item__label">Nodes</span>
            </div>
            <div className="stat-item">
              <span className="stat-item__value">{runningNodes}</span>
              <span className="stat-item__label">Running</span>
            </div>
            <div className="stat-item">
              <span className="stat-item__value">{links.length}</span>
              <span className="stat-item__label">Links</span>
            </div>
            <div className="stat-item">
              <span className="stat-item__value">{activeLinks}</span>
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
          <TopologyCanvas
            nodes={nodes}
            links={links}
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
        {selectedNode && (
          <NodeDetailPanel node={selectedNode} onClose={handleCloseNodePanel} />
        )}
        {selectedLink && (
          <div className="topology-detail__panels">
            <LinkDetailPanel link={selectedLink} onClose={handleCloseLinkPanel} />
            <TrafficControlPanel
              link={selectedLink}
              onSave={handlePolicySave}
              onReset={handlePolicyReset}
              onClose={handleCloseLinkPanel}
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
