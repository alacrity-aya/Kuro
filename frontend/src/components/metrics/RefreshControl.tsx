/**
 * Refresh Control Component
 * 用于控制仪表板自动刷新
 */

import './RefreshControl.css';
import {
  REFRESH_INTERVALS,
  formatLastRefreshTime,
  type RefreshInterval,
} from '../../hooks/useAutoRefresh';

interface RefreshControlProps {
  /** 当前刷新间隔 (ms) */
  interval: number;
  /** 设置刷新间隔 */
  onIntervalChange: (ms: number) => void;
  /** 是否启用自动刷新 */
  enabled: boolean;
  /** 设置是否启用 */
  onEnabledChange: (enabled: boolean) => void;
  /** 手动刷新回调 */
  onRefresh: () => void;
  /** 上次刷新时间 */
  lastRefreshTime?: Date | null;
  /** 是否正在刷新 */
  isRefreshing?: boolean;
  /** 自定义刷新间隔选项 */
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
      {/* 手动刷新按钮 */}
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

      {/* 自动刷新开关 */}
      <button
        className={`refresh-control__btn refresh-control__btn--toggle ${enabled ? 'active' : ''}`}
        onClick={() => onEnabledChange(!enabled)}
        title={enabled ? 'Pause auto-refresh' : 'Start auto-refresh'}
      >
        {enabled ? '⏸' : '▶'}
      </button>

      {/* 刷新间隔选择 */}
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

      {/* 上次刷新时间 */}
      <span className="refresh-control__time">
        {formatLastRefreshTime(lastRefreshTime)}
      </span>
    </div>
  );
}
