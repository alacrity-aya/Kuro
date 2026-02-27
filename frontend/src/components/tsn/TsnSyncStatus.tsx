import type { TimeSyncStatus, TopologyNode } from '../../types/api';
import './TsnSyncStatus.css';

// ============================================================================
// Types
// ============================================================================

interface TsnSyncStatusProps {
  nodes: TopologyNode[];
  syncStatuses: TimeSyncStatus[];
}

// ============================================================================
// Helper Functions
// ============================================================================

function formatOffset(offsetNs: number): string {
  if (Math.abs(offsetNs) < 1000) {
    return `${offsetNs} ns`;
  } else if (Math.abs(offsetNs) < 1000000) {
    return `${(offsetNs / 1000).toFixed(2)} μs`;
  } else {
    return `${(offsetNs / 1000000).toFixed(2)} ms`;
  }
}

function getClockClassDescription(clockClass: number): string {
  // PTP clock class definitions
  if (clockClass === 6) return 'Locked to GPS';
  if (clockClass === 7) return 'Locked to PRTC';
  if (clockClass === 52) return 'Locked to PTP';
  if (clockClass === 187) return 'Holdover';
  if (clockClass === 248) return 'Free Running';
  return `Class ${clockClass}`;
}

function getSyncQualityClass(offset: number): string {
  const absOffset = Math.abs(offset);
  if (absOffset < 100) return 'excellent';
  if (absOffset < 1000) return 'good';
  if (absOffset < 10000) return 'fair';
  return 'poor';
}

// ============================================================================
// Component
// ============================================================================

function TsnSyncStatus({ nodes, syncStatuses }: TsnSyncStatusProps) {
  // Create a map of nodeId to sync status for quick lookup
  const syncStatusMap = new Map<string, TimeSyncStatus>();
  syncStatuses.forEach((status) => {
    syncStatusMap.set(status.nodeId, status);
  });

  // Find grandmaster node
  const grandmasterNode = nodes.find((node) => {
    const status = syncStatusMap.get(node.id);
    return status?.grandmasterId === node.id;
  });

  if (nodes.length === 0) {
    return (
      <div className="tsn-sync-status tsn-sync-status--empty">
        <span className="tsn-sync-status__empty-text">No nodes available</span>
      </div>
    );
  }

  return (
    <div className="tsn-sync-status">
      <div className="tsn-sync-status__header">
        <span className="tsn-sync-status__icon">🕐</span>
        <span className="tsn-sync-status__title">Time Synchronization</span>
        {grandmasterNode && (
          <span className="tsn-sync-status__gm-badge">
            GM: {grandmasterNode.name}
          </span>
        )}
      </div>

      <div className="tsn-sync-status__nodes">
        {nodes.map((node) => {
          const status = syncStatusMap.get(node.id);
          const isGrandmaster = status?.grandmasterId === node.id;
          const syncQuality = status ? getSyncQualityClass(status.offset) : 'unknown';

          return (
            <div
              key={node.id}
              className={`tsn-sync-node tsn-sync-node--${syncQuality} ${isGrandmaster ? 'tsn-sync-node--gm' : ''}`}
            >
              <div className="tsn-sync-node__header">
                <div className="tsn-sync-node__info">
                  <span className="tsn-sync-node__name">{node.name}</span>
                  <span className="tsn-sync-node__role">{node.role}</span>
                </div>
                <div className="tsn-sync-node__status">
                  {isGrandmaster ? (
                    <span className="tsn-sync-node__gm-tag">Grandmaster</span>
                  ) : status?.synced ? (
                    <span className="tsn-sync-node__sync-indicator tsn-sync-node__sync-indicator--synced">
                      ● Synced
                    </span>
                  ) : (
                    <span className="tsn-sync-node__sync-indicator tsn-sync-node__sync-indicator--unsynced">
                      ○ Unsynced
                    </span>
                  )}
                </div>
              </div>

              {status && (
                <div className="tsn-sync-node__details">
                  <div className="tsn-sync-node__metric">
                    <span className="tsn-sync-node__metric-label">Offset</span>
                    <span className={`tsn-sync-node__metric-value tsn-sync-node__metric-value--${syncQuality}`}>
                      {formatOffset(status.offset)}
                    </span>
                  </div>
                  <div className="tsn-sync-node__metric">
                    <span className="tsn-sync-node__metric-label">Clock Class</span>
                    <span className="tsn-sync-node__metric-value">
                      {getClockClassDescription(status.clockClass)}
                    </span>
                  </div>
                  <div className="tsn-sync-node__metric">
                    <span className="tsn-sync-node__metric-label">Last Sync</span>
                    <span className="tsn-sync-node__metric-value tsn-sync-node__metric-value--time">
                      {new Date(status.lastSyncTime).toLocaleTimeString()}
                    </span>
                  </div>
                </div>
              )}

              {!status && (
                <div className="tsn-sync-node__no-data">
                  No synchronization data available
                </div>
              )}
            </div>
          );
        })}
      </div>

      <div className="tsn-sync-status__legend">
        <div className="tsn-sync-status__legend-item">
          <span className="tsn-sync-status__legend-dot tsn-sync-status__legend-dot--excellent"></span>
          <span>Excellent (&lt;100ns)</span>
        </div>
        <div className="tsn-sync-status__legend-item">
          <span className="tsn-sync-status__legend-dot tsn-sync-status__legend-dot--good"></span>
          <span>Good (&lt;1μs)</span>
        </div>
        <div className="tsn-sync-status__legend-item">
          <span className="tsn-sync-status__legend-dot tsn-sync-status__legend-dot--fair"></span>
          <span>Fair (&lt;10μs)</span>
        </div>
        <div className="tsn-sync-status__legend-item">
          <span className="tsn-sync-status__legend-dot tsn-sync-status__legend-dot--poor"></span>
          <span>Poor (&gt;10μs)</span>
        </div>
      </div>
    </div>
  );
}

export default TsnSyncStatus;
