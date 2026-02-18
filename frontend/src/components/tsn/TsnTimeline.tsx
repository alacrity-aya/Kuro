import { useMemo } from 'react';
import type { TSNSchedule, TopologyLink } from '../../types/api';
import './TsnTimeline.css';

// ============================================================================
// Types
// ============================================================================

interface TsnTimelineProps {
  schedule: TSNSchedule;
  links: TopologyLink[];
}

// ============================================================================
// Helper Functions
// ============================================================================

function formatTime(us: number): string {
  if (us < 1000) {
    return `${us}μs`;
  }
  return `${(us / 1000).toFixed(1)}ms`;
}

function getTrafficClassColor(trafficClass: string): string {
  switch (trafficClass) {
    case 'ST': // Scheduled Traffic (highest priority)
      return '#e94560';
    case 'AVB': // Audio Video Bridging
      return '#00d9ff';
    case 'BE': // Best Effort
      return '#00ff88';
    default:
      return '#888';
  }
}

function getTrafficClassLabel(trafficClass: string): string {
  switch (trafficClass) {
    case 'ST':
      return 'Scheduled';
    case 'AVB':
      return 'AVB';
    case 'BE':
      return 'Best Effort';
    default:
      return trafficClass;
  }
}

// ============================================================================
// Component
// ============================================================================

function TsnTimeline({ schedule, links }: TsnTimelineProps) {
  const { cycleTime, slots } = schedule;

  // Create a map of linkId to link for quick lookup
  const linkMap = useMemo(() => {
    const map = new Map<string, TopologyLink>();
    links.forEach((link) => {
      map.set(link.id, link);
    });
    return map;
  }, [links]);

  // Calculate timeline segments
  const timelineSegments = useMemo(() => {
    return slots.map((slot) => {
      const startPercent = (slot.startTime / cycleTime) * 100;
      const durationPercent = (slot.duration / cycleTime) * 100;
      const link = linkMap.get(slot.linkId);

      return {
        ...slot,
        startPercent,
        durationPercent,
        link,
      };
    });
  }, [slots, cycleTime, linkMap]);

  // Group slots by traffic class for summary
  const trafficClassSummary = useMemo(() => {
    const summary = new Map<string, number>();
    slots.forEach((slot) => {
      const current = summary.get(slot.trafficClass) || 0;
      summary.set(slot.trafficClass, current + slot.duration);
    });
    return summary;
  }, [slots]);

  if (slots.length === 0) {
    return (
      <div className="tsn-timeline tsn-timeline--empty">
        <span className="tsn-timeline__empty-icon">📊</span>
        <span className="tsn-timeline__empty-text">No TSN schedule configured</span>
      </div>
    );
  }

  return (
    <div className="tsn-timeline">
      <div className="tsn-timeline__header">
        <span className="tsn-timeline__icon">⏱️</span>
        <span className="tsn-timeline__title">TSN Schedule Timeline</span>
        <span className="tsn-timeline__cycle">Cycle: {formatTime(cycleTime)}</span>
      </div>

      {/* Timeline Track */}
      <div className="tsn-timeline__track-container">
        <div className="tsn-timeline__track">
          {timelineSegments.map((segment) => (
            <div
              key={segment.id}
              className="tsn-timeline__slot"
              style={{
                left: `${segment.startPercent}%`,
                width: `${segment.durationPercent}%`,
                backgroundColor: segment.color || getTrafficClassColor(segment.trafficClass),
              }}
              title={`${getTrafficClassLabel(segment.trafficClass)} - ${formatTime(segment.duration)}`}
            >
              <span className="tsn-timeline__slot-label">
                {segment.trafficClass}
              </span>
            </div>
          ))}
        </div>

        {/* Time Markers */}
        <div className="tsn-timeline__markers">
          {[0, 25, 50, 75, 100].map((percent) => (
            <div
              key={percent}
              className="tsn-timeline__marker"
              style={{ left: `${percent}%` }}
            >
              <div className="tsn-timeline__marker-line"></div>
              <span className="tsn-timeline__marker-label">
                {formatTime((cycleTime * percent) / 100)}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Slot Details */}
      <div className="tsn-timeline__details">
        <div className="tsn-timeline__details-header">Slot Details</div>
        <div className="tsn-timeline__slots-list">
          {slots.map((slot, index) => {
            const link = linkMap.get(slot.linkId);
            return (
              <div key={slot.id} className="tsn-timeline__slot-detail">
                <div
                  className="tsn-timeline__slot-color"
                  style={{ backgroundColor: slot.color || getTrafficClassColor(slot.trafficClass) }}
                ></div>
                <div className="tsn-timeline__slot-info">
                  <span className="tsn-timeline__slot-index">#{index + 1}</span>
                  <span className="tsn-timeline__slot-class">
                    {getTrafficClassLabel(slot.trafficClass)}
                  </span>
                  {link && (
                    <span className="tsn-timeline__slot-link">
                      {link.sourceId} → {link.targetId}
                    </span>
                  )}
                </div>
                <div className="tsn-timeline__slot-timing">
                  <span className="tsn-timeline__slot-start">
                    {formatTime(slot.startTime)}
                  </span>
                  <span className="tsn-timeline__slot-duration">
                    ({formatTime(slot.duration)})
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Traffic Class Summary */}
      <div className="tsn-timeline__summary">
        <div className="tsn-timeline__summary-header">Bandwidth Allocation</div>
        <div className="tsn-timeline__summary-bars">
          {Array.from(trafficClassSummary.entries()).map(([trafficClass, duration]) => {
            const percentage = (duration / cycleTime) * 100;
            return (
              <div key={trafficClass} className="tsn-timeline__summary-item">
                <div className="tsn-timeline__summary-label">
                  <span
                    className="tsn-timeline__summary-dot"
                    style={{ backgroundColor: getTrafficClassColor(trafficClass) }}
                  ></span>
                  <span>{getTrafficClassLabel(trafficClass)}</span>
                </div>
                <div className="tsn-timeline__summary-bar-container">
                  <div
                    className="tsn-timeline__summary-bar"
                    style={{
                      width: `${percentage}%`,
                      backgroundColor: getTrafficClassColor(trafficClass),
                    }}
                  ></div>
                  <span className="tsn-timeline__summary-percentage">
                    {percentage.toFixed(1)}%
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

export default TsnTimeline;
