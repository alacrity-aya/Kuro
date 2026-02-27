import { useEffect, useCallback, useReducer, useMemo, useRef } from 'react';
import type { TrafficPolicy, TopologyLink } from '../types/api';
import './TrafficControlPanel.css';

// ============================================================================
// Types
// ============================================================================

interface TrafficControlPanelProps {
  link: TopologyLink | null;
  onSave?: (linkId: string, policy: TrafficPolicy) => void;
  onReset?: (linkId: string) => void;
  onClose?: () => void;
  tsnMode?: boolean; // TSN mode for microsecond precision
}

interface SliderConfig {
  min: number;
  max: number;
  step: number;
  unit: string;
  format: (value: number) => string;
}

// ============================================================================
// Slider Configurations
// ============================================================================

const BANDWIDTH_CONFIG: SliderConfig = {
  min: 0.1,
  max: 1000,
  step: 0.1,
  unit: 'Mbps',
  format: (v) => v >= 1000 ? `${(v / 1000).toFixed(1)} Gbps` : `${v.toFixed(1)} Mbps`,
};

// Standard latency config (milliseconds)
const LATENCY_CONFIG_MS: SliderConfig = {
  min: 0,
  max: 1000,
  step: 1,
  unit: 'ms',
  format: (v) => `${v} ms`,
};

// TSN latency config (microseconds)
const LATENCY_CONFIG_US: SliderConfig = {
  min: 0,
  max: 100000, // 100ms in microseconds
  step: 10,
  unit: 'μs',
  format: (v) => {
    if (v >= 1000) {
      return `${v} μs (${(v / 1000).toFixed(2)} ms)`;
    }
    return `${v} μs`;
  },
};

// Standard jitter config (milliseconds)
const JITTER_CONFIG_MS: SliderConfig = {
  min: 0,
  max: 500,
  step: 1,
  unit: 'ms',
  format: (v) => `${v} ms`,
};

// TSN jitter config (microseconds)
const JITTER_CONFIG_US: SliderConfig = {
  min: 0,
  max: 50000, // 50ms in microseconds
  step: 5,
  unit: 'μs',
  format: (v) => {
    if (v >= 1000) {
      return `${v} μs (${(v / 1000).toFixed(2)} ms)`;
    }
    return `${v} μs`;
  },
};

const PACKET_LOSS_CONFIG: SliderConfig = {
  min: 0,
  max: 100,
  step: 0.1,
  unit: '%',
  format: (v) => `${v.toFixed(1)}%`,
};

// ============================================================================
// Parse Policy String Helpers
// ============================================================================

function parseBandwidth(value: string): number {
  // Parse "10Mbps", "1Gbps", "500Kbps" etc.
  const match = value.match(/^(\d+(?:\.\d+)?)(Kbps|Mbps|Gbps)?$/i);
  if (!match) return 10; // default 10Mbps
  
  const num = parseFloat(match[1]);
  const unit = (match[2] ?? 'Mbps').toLowerCase();
  
  switch (unit) {
    case 'kbps': return num / 1000;
    case 'mbps': return num;
    case 'gbps': return num * 1000;
    default: return num;
  }
}

function parseLatency(value: string, tsnMode: boolean): number {
  const match = value.match(/^(\d+(?:\.\d+)?)(ms|us|s)?$/i);
  if (!match) return 0;
  
  const num = parseFloat(match[1]);
  const unit = (match[2] ?? 'ms').toLowerCase();
  
  // Return value in appropriate unit based on mode
  if (tsnMode) {
    // In TSN mode, return microseconds
    switch (unit) {
      case 'us': return num;
      case 'ms': return num * 1000;
      case 's': return num * 1000000;
      default: return num * 1000; // assume ms if no unit
    }
  } else {
    // In standard mode, return milliseconds
    switch (unit) {
      case 'us': return num / 1000;
      case 'ms': return num;
      case 's': return num * 1000;
      default: return num;
    }
  }
}

function parseJitter(value: string, tsnMode: boolean): number {
  return parseLatency(value, tsnMode);
}

function parsePacketLoss(value: string): number {
  // Parse "0.5%", "1%", etc.
  const match = value.match(/^(\d+(?:\.\d+)?)%?$/);
  if (!match) return 0;
  return parseFloat(match[1]);
}

// ============================================================================
// Slider Component
// ============================================================================

interface SliderProps {
  label: string;
  value: number;
  config: SliderConfig;
  onChange: (value: number) => void;
  disabled?: boolean;
}

function Slider({ label, value, config, onChange, disabled }: SliderProps) {
  return (
    <div className={`tc-slider ${disabled ? 'tc-slider--disabled' : ''}`}>
      <div className="tc-slider__header">
        <span className="tc-slider__label">{label}</span>
        <span className="tc-slider__value">{config.format(value)}</span>
      </div>
      <input
        type="range"
        className="tc-slider__input"
        min={config.min}
        max={config.max}
        step={config.step}
        value={value}
        onChange={(e) => onChange(parseFloat(e.target.value))}
        disabled={disabled}
      />
      <div className="tc-slider__bounds">
        <span>{config.format(config.min)}</span>
        <span>{config.format(config.max)}</span>
      </div>
    </div>
  );
}

// ============================================================================
// Main Component
// ============================================================================

// Helper to extract values from link policy
function getPolicyValues(
  link: TrafficControlPanelProps['link'],
  tsnMode: boolean
): { bandwidth: number; latency: number; jitter: number; packetLoss: number } {
  if (link?.policy) {
    return {
      bandwidth: parseBandwidth(link.policy.bandwidth),
      latency: parseLatency(link.policy.latency, tsnMode),
      jitter: parseJitter(link.policy.jitter, tsnMode),
      packetLoss: parsePacketLoss(link.policy.packetLoss),
    };
  }
  return { bandwidth: 10, latency: 0, jitter: 0, packetLoss: 0 };
}

// State type for reducer
interface SliderState {
  bandwidth: number;
  latency: number;
  jitter: number;
  packetLoss: number;
  originalValues: { bandwidth: number; latency: number; jitter: number; packetLoss: number } | null;
  hasChanges: boolean;
}

// Action types
type SliderAction =
  | { type: 'SET_BANDWIDTH'; value: number }
  | { type: 'SET_LATENCY'; value: number }
  | { type: 'SET_JITTER'; value: number }
  | { type: 'SET_PACKET_LOSS'; value: number }
  | { type: 'RESET'; values: SliderState['originalValues'] }
  | { type: 'SYNC_LINK'; values: { bandwidth: number; latency: number; jitter: number; packetLoss: number }; hasOriginal: boolean };

// Reducer function
function sliderReducer(state: SliderState, action: SliderAction): SliderState {
  switch (action.type) {
    case 'SET_BANDWIDTH':
      return { ...state, bandwidth: action.value };
    case 'SET_LATENCY':
      return { ...state, latency: action.value };
    case 'SET_JITTER':
      return { ...state, jitter: action.value };
    case 'SET_PACKET_LOSS':
      return { ...state, packetLoss: action.value };
    case 'RESET':
      if (action.values) {
        return {
          bandwidth: action.values.bandwidth,
          latency: action.values.latency,
          jitter: action.values.jitter,
          packetLoss: action.values.packetLoss,
          originalValues: action.values,
          hasChanges: false,
        };
      }
      return state;
    case 'SYNC_LINK':
      return {
        bandwidth: action.values.bandwidth,
        latency: action.values.latency,
        jitter: action.values.jitter,
        packetLoss: action.values.packetLoss,
        originalValues: action.hasOriginal ? action.values : null,
        hasChanges: false,
      };
    default:
      return state;
  }
}

// Check if values have changed
function checkHasChanges(
  current: { bandwidth: number; latency: number; jitter: number; packetLoss: number },
  original: SliderState['originalValues']
): boolean {
  if (!original) return false;
  return (
    current.bandwidth !== original.bandwidth ||
    current.latency !== original.latency ||
    current.jitter !== original.jitter ||
    current.packetLoss !== original.packetLoss
  );
}

function TrafficControlPanel({ link, onSave, onReset, onClose, tsnMode = false }: TrafficControlPanelProps) {
  // Calculate initial values from link policy
  const initialValues = useMemo(
    () => getPolicyValues(link, tsnMode),
    [link, tsnMode]
  );

  // Use reducer to manage all slider state
  const [state, dispatch] = useReducer(sliderReducer, {
    bandwidth: initialValues.bandwidth,
    latency: initialValues.latency,
    jitter: initialValues.jitter,
    packetLoss: initialValues.packetLoss,
    originalValues: link?.policy ? initialValues : null,
    hasChanges: false,
  });

  // Track previous link id to detect changes
  const prevLinkIdRef = useRef(link?.id);
  const prevTsnModeRef = useRef(tsnMode);

  // Get appropriate configs based on TSN mode
  const latencyConfig = tsnMode ? LATENCY_CONFIG_US : LATENCY_CONFIG_MS;
  const jitterConfig = tsnMode ? JITTER_CONFIG_US : JITTER_CONFIG_MS;

  // Destructure state for easier access
  const { bandwidth, latency, jitter, packetLoss, originalValues } = state;

  // Update values when link changes (different link selected)
  useEffect(() => {
    const linkChanged = prevLinkIdRef.current !== link?.id;
    const tsnModeChanged = prevTsnModeRef.current !== tsnMode;
    
    if (linkChanged || tsnModeChanged) {
      prevLinkIdRef.current = link?.id;
      prevTsnModeRef.current = tsnMode;
      
      const newValues = getPolicyValues(link, tsnMode);
      dispatch({ type: 'SYNC_LINK', values: newValues, hasOriginal: !!link?.policy });
    }
  }, [link, tsnMode]);

  // Check for changes - derived state, no useEffect needed
  const currentHasChanges = checkHasChanges({ bandwidth, latency, jitter, packetLoss }, originalValues);

  // Format policy for API
  const formatPolicy = useCallback((): TrafficPolicy => {
    const latencyValue = tsnMode 
      ? `${latency}us` 
      : `${latency}ms`;
    const jitterValue = tsnMode 
      ? `${jitter}us` 
      : `${jitter}ms`;
    
    return {
      bandwidth: bandwidth >= 1000 
        ? `${(bandwidth / 1000).toFixed(1)}Gbps` 
        : `${bandwidth.toFixed(1)}Mbps`,
      latency: latencyValue,
      jitter: jitterValue,
      packetLoss: `${packetLoss.toFixed(1)}%`,
    };
  }, [bandwidth, latency, jitter, packetLoss, tsnMode]);

  // Handle save
  const handleSave = useCallback(() => {
    if (link && onSave) {
      onSave(link.id, formatPolicy());
      dispatch({ type: 'RESET', values: { bandwidth, latency, jitter, packetLoss } });
    }
  }, [link, onSave, formatPolicy, bandwidth, latency, jitter, packetLoss]);

  // Handle reset
  const handleReset = useCallback(() => {
    if (originalValues) {
      dispatch({ type: 'RESET', values: originalValues });
    } else if (link && onReset) {
      onReset(link.id);
    }
  }, [originalValues, link, onReset]);

  if (!link) {
    return (
      <div className="traffic-control-panel traffic-control-panel--empty">
        <div className="tcp-empty">
          <span className="tcp-empty__icon">🔗</span>
          <span className="tcp-empty__text">Select a link to adjust traffic parameters</span>
        </div>
      </div>
    );
  }

  return (
    <div className="traffic-control-panel">
      <div className="tcp-header">
        <h3 className="tcp-title">Traffic Control</h3>
        {onClose && (
          <button className="tcp-close" onClick={onClose} title="Close">
            ×
          </button>
        )}
      </div>

      <div className="tcp-link-info">
        <span className="tcp-link-info__label">Link:</span>
        <span className="tcp-link-info__value">
          {link.sourceId} → {link.targetId}
        </span>
      </div>

      <div className="tcp-sliders">
        <Slider
          label="Bandwidth"
          value={bandwidth}
          config={BANDWIDTH_CONFIG}
          onChange={(value) => dispatch({ type: 'SET_BANDWIDTH', value })}
        />
        <Slider
          label={tsnMode ? "Latency (TSN)" : "Latency"}
          value={latency}
          config={latencyConfig}
          onChange={(value) => dispatch({ type: 'SET_LATENCY', value })}
        />
        <Slider
          label={tsnMode ? "Jitter (TSN)" : "Jitter"}
          value={jitter}
          config={jitterConfig}
          onChange={(value) => dispatch({ type: 'SET_JITTER', value })}
        />
        <Slider
          label="Packet Loss"
          value={packetLoss}
          config={PACKET_LOSS_CONFIG}
          onChange={(value) => dispatch({ type: 'SET_PACKET_LOSS', value })}
        />
      </div>

      {tsnMode && (
        <div className="tcp-tsn-notice">
          <span className="tcp-tsn-notice__icon">⚡</span>
          <span className="tcp-tsn-notice__text">
            TSN mode: Latency and jitter are in microseconds (μs) for precise timing control.
          </span>
        </div>
      )}

      <div className="tcp-preview">
        <span className="tcp-preview__label">Preview:</span>
        <code className="tcp-preview__code">
          {formatPolicy().bandwidth}, {formatPolicy().latency}, {formatPolicy().jitter}, {formatPolicy().packetLoss}
        </code>
      </div>

      <div className="tcp-actions">
        <button
          className="tcp-btn tcp-btn--secondary"
          onClick={handleReset}
          disabled={!currentHasChanges && !originalValues}
        >
          Reset
        </button>
        <button
          className="tcp-btn tcp-btn--primary"
          onClick={handleSave}
          disabled={!currentHasChanges}
        >
          Apply Changes
        </button>
      </div>

      {currentHasChanges && (
        <div className="tcp-unsaved">
          You have unsaved changes
        </div>
      )}
    </div>
  );
}

export default TrafficControlPanel;
