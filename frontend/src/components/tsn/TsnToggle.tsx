import type { TSNConfig } from '../../types/api';
import './TsnToggle.css';

// ============================================================================
// Types
// ============================================================================

interface TsnToggleProps {
  config: TSNConfig;
  onToggle: (enabled: boolean) => void;
}

// ============================================================================
// Component
// ============================================================================

function TsnToggle({ config, onToggle }: TsnToggleProps) {
  const { enabled, cycleTime } = config;

  return (
    <div className="tsn-toggle">
      <div className="tsn-toggle__header">
        <span className="tsn-toggle__icon">⚡</span>
        <span className="tsn-toggle__label">TSN Mode</span>
      </div>
      <div className="tsn-toggle__control">
        <label className="tsn-toggle__switch">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => onToggle(e.target.checked)}
          />
          <span className="tsn-toggle__slider"></span>
        </label>
        <span className={`tsn-toggle__status ${enabled ? 'tsn-toggle__status--on' : 'tsn-toggle__status--off'}`}>
          {enabled ? 'ON' : 'OFF'}
        </span>
      </div>
      {enabled && (
        <div className="tsn-toggle__info">
          <span className="tsn-toggle__cycle">
            Cycle: {(cycleTime / 1000).toFixed(1)} ms
          </span>
        </div>
      )}
    </div>
  );
}

export default TsnToggle;
