import { useMemo } from 'react';
import type { TSNSchedule, TSNSlot } from '../../types/api';
import './ScheduleTimeline.css';

// ============================================================================
// Types
// ============================================================================

interface ScheduleTimelineProps {
  schedule: TSNSchedule;
  currentCyclePosition?: number; // in microseconds
}

// ============================================================================
// Constants
// ============================================================================

const TRAFFIC_CLASS_CONFIG: Record<TSNSlot['trafficClass'], { label: string; color: string }> = {
  ST: { label: 'Scheduled Traffic', color: '#ef4444' },
  BE: { label: 'Best Effort', color: '#3b82f6' },
  AVB: { label: 'Audio/Video', color: '#10b981' },
};

// ============================================================================
// Component
// ============================================================================

export function ScheduleTimeline({ schedule, currentCyclePosition }: ScheduleTimelineProps) {
  const cycleTimeMs = schedule.cycleTime / 1000;
  
  const sortedSlots = useMemo(() => {
    return [...schedule.slots].sort((a, b) => a.startTime - b.startTime);
  }, [schedule.slots]);

  return (
    <div className="schedule-timeline">
      <div className="schedule-timeline__header">
        <h4 className="schedule-timeline__title">TSN Schedule</h4>
        <span className="schedule-timeline__cycle">
          Cycle: {schedule.cycleTime} μs ({cycleTimeMs.toFixed(1)} ms)
        </span>
      </div>

      {/* Timeline Track */}
      <div className="schedule-timeline__track-container">
        <div className="schedule-timeline__track">
          {/* Time markers */}
          <div className="schedule-timeline__markers">
            {[0, 25, 50, 75, 100].map((percent) => (
              <div 
                key={percent} 
                className="schedule-timeline__marker"
                style={{ left: `${percent}%` }}
              >
                <span className="schedule-timeline__marker-time">
                  {Math.round(schedule.cycleTime * percent / 100)} μs
                </span>
              </div>
            ))}
          </div>

          {/* Slots */}
          <div className="schedule-timeline__slots">
            {sortedSlots.map((slot) => {
              const startPercent = (slot.startTime / schedule.cycleTime) * 100;
              const widthPercent = (slot.duration / schedule.cycleTime) * 100;
              const classConfig = TRAFFIC_CLASS_CONFIG[slot.trafficClass];
              
              return (
                <div
                  key={slot.id}
                  className="schedule-timeline__slot"
                  style={{
                    left: `${startPercent}%`,
                    width: `${widthPercent}%`,
                    backgroundColor: slot.color || classConfig.color,
                  }}
                  title={`${slot.id}: ${slot.startTime}-${slot.startTime + slot.duration} μs`}
                >
                  <span className="schedule-timeline__slot-label">
                    {slot.trafficClass}
                  </span>
                </div>
              );
            })}
          </div>

          {/* Current Position Indicator */}
          {currentCyclePosition !== undefined && (
            <div
              className="schedule-timeline__indicator"
              style={{ 
                left: `${(currentCyclePosition / schedule.cycleTime) * 100}%` 
              }}
            />
          )}
        </div>
      </div>

      {/* Legend */}
      <div className="schedule-timeline__legend">
        {Object.entries(TRAFFIC_CLASS_CONFIG).map(([key, config]) => (
          <div key={key} className="schedule-timeline__legend-item">
            <span
              className="schedule-timeline__legend-color"
              style={{ backgroundColor: config.color }}
            />
            <span className="schedule-timeline__legend-label">{config.label}</span>
          </div>
        ))}
      </div>

      {/* Slot Details */}
      <div className="schedule-timeline__details">
        <h5 className="schedule-timeline__details-title">Slot Details</h5>
        <div className="schedule-timeline__details-list">
          {sortedSlots.map((slot) => {
            const classConfig = TRAFFIC_CLASS_CONFIG[slot.trafficClass];
            return (
              <div key={slot.id} className="schedule-timeline__detail-item">
                <span
                  className="schedule-timeline__detail-color"
                  style={{ backgroundColor: slot.color || classConfig.color }}
                />
                <span className="schedule-timeline__detail-id">{slot.id}</span>
                <span className="schedule-timeline__detail-range">
                  {slot.startTime} - {slot.startTime + slot.duration} μs
                </span>
                <span className="schedule-timeline__detail-class">
                  {classConfig.label}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
