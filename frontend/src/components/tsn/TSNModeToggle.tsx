import type { TSNConfig } from '../../types/api';
import './TSNModeToggle.css';

// ============================================================================
// Types
// ============================================================================

interface TSNModeToggleProps {
  config: TSNConfig;
  onToggle: (enabled: boolean) => void;
  onConfigChange: (config: Partial<TSNConfig>) => void;
}

// ============================================================================
// Component
// ============================================================================

export function TSNModeToggle({ config, onToggle, onConfigChange }: TSNModeToggleProps) {
  return (
    <div className="tsn-toggle">
      <div className="tsn-toggle__header">
        <div className="tsn-toggle__switch-container">
          <label className="tsn-toggle__switch">
            <input
              type="checkbox"
              checked={config.enabled}
              onChange={(e) => onToggle(e.target.checked)}
            />
            <span className="tsn-toggle__slider"></span>
          </label>
          <div className="tsn-toggle__label-group">
            <span className="tsn-toggle__label">TSN Mode</span>
            <span className="tsn-toggle__status">
              {config.enabled ? 'Enabled' : 'Disabled'}
            </span>
          </div>
        </div>
      </div>

      {config.enabled && (
        <div className="tsn-toggle__config">
          <div className="tsn-config-item">
            <label className="tsn-config-item__label">Cycle Time</label>
            <div className="tsn-config-item__input-group">
              <input
                type="number"
                className="tsn-config-item__input"
                value={config.cycleTime}
                onChange={(e) => onConfigChange({ cycleTime: parseInt(e.target.value) || 100000 })}
                min={1000}
                max={10000000}
                step={1000}
              />
              <span className="tsn-config-item__unit">μs</span>
            </div>
            <span className="tsn-config-item__hint">
              ({(config.cycleTime / 1000).toFixed(1)} ms)
            </span>
          </div>

          <div className="tsn-config-item">
            <label className="tsn-config-item__label">Sync Interval</label>
            <div className="tsn-config-item__input-group">
              <input
                type="number"
                className="tsn-config-item__input"
                value={config.syncInterval}
                onChange={(e) => onConfigChange({ syncInterval: parseInt(e.target.value) || 125 })}
                min={16}
                max={1000}
                step={1}
              />
              <span className="tsn-config-item__unit">ms</span>
            </div>
          </div>

          <div className="tsn-toggle__info">
            <span className="tsn-toggle__info-icon">ℹ️</span>
            <span className="tsn-toggle__info-text">
              TSN mode displays latency in microseconds (μs) for precise timing control.
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
