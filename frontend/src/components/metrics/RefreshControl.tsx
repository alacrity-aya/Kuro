/**
 * Refresh Control Component
 * Used to control dashboard auto-refresh
 */

import './RefreshControl.css';
import {
  REFRESH_INTERVALS,
  formatLastRefreshTime,
  type RefreshInterval,
} from '../../hooks/useAutoRefresh';

interface RefreshControlProps {
  /** Current refresh interval (ms) */
  interval: number;
  /** Set refresh interval */
  onIntervalChange: (ms: number) => void;
  /** Whether auto-refresh is enabled */
  enabled: boolean;
  /** Set enabled state */
  onEnabledChange: (enabled: boolean) => void;
  /** Manual refresh callback */
  onRefresh: () => void;
  /** Last refresh time */
  lastRefreshTime?: Date | null;
  /** Is refreshing */
  isRefreshing?: boolean;
  /** Custom refresh interval options */
  intervals?: RefreshInterval[];
}

export function RefreshControl({
  interval,
  onIntervalChange,
  enabled,
  onEnabledChange,
  onRefresh,
  lastRefreshTime = null,
  isRefreshing = false,
  intervals = REFRESH_INTERVALS,
}: RefreshControlProps) {
  return (
    <div className="refresh-control">
      {/* Manual refresh button */}
      <button
        className="refresh-control__btn refresh-control__btn--refresh"
        onClick={onRefresh}
        disabled={isRefreshing}
        title="Refresh now"
      >
        <span className={`refresh-control__icon ${isRefreshing ? 'spinning' : ''}`}>
          ↻
        </span>
      </button>

      {/* Auto-refresh toggle */}
      <button
        className={`refresh-control__btn refresh-control__btn--toggle ${enabled ? 'active' : ''}`}
        onClick={() => onEnabledChange(!enabled)}
        title={enabled ? 'Pause auto-refresh' : 'Start auto-refresh'}
      >
        {enabled ? '⏸' : '▶'}
      </button>

      {/* Refresh interval selector */}
      <select
        className="refresh-control__select"
        value={interval}
        onChange={(e) => onIntervalChange(Number(e.target.value))}
        disabled={!enabled}
        title="Refresh interval"
      >
        {intervals.map((opt) => (
          <option key={opt.value} value={opt.value}>
            {opt.label}
          </option>
        ))}
      </select>

      {/* Last refresh time */}
      <span className="refresh-control__time">
        {formatLastRefreshTime(lastRefreshTime)}
      </span>
    </div>
  );
}
