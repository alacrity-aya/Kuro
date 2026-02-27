import { useReducer, useCallback, memo, useMemo, useRef, useEffect } from 'react';
import type { TrafficPolicy } from '../../types/api';
import './LinkConfigPanel.css';

// ============================================================================
// Types
// ============================================================================

export interface LinkConfigPanelProps {
  linkId: string | null;
  sourceName: string;
  targetName: string;
  policy: TrafficPolicy | null;
  onPolicyChange?: (linkId: string, policy: TrafficPolicy) => void;
  onDelete?: (linkId: string) => void;
  onClose?: () => void;
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
  format: (v) => (v >= 1000 ? `${(v / 1000).toFixed(1)} Gbps` : `${v.toFixed(1)} Mbps`),
};

const LATENCY_CONFIG: SliderConfig = {
  min: 0,
  max: 1000,
  step: 1,
  unit: 'ms',
  format: (v) => `${v} ms`,
};

const JITTER_CONFIG: SliderConfig = {
  min: 0,
  max: 500,
  step: 1,
  unit: 'ms',
  format: (v) => `${v} ms`,
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
  const match = value.match(/^(\d+(?:\.\d+)?)(Kbps|Mbps|Gbps)?$/i);
  if (!match) return 10;

  const num = parseFloat(match[1]);
  const unit = (match[2] ?? 'Mbps').toLowerCase();

  switch (unit) {
    case 'kbps':
      return num / 1000;
    case 'mbps':
      return num;
    case 'gbps':
      return num * 1000;
    default:
      return num;
  }
}

function parseLatency(value: string): number {
  const match = value.match(/^(\d+(?:\.\d+)?)(ms|us|s)?$/i);
  if (!match) return 0;

  const num = parseFloat(match[1]);
  const unit = (match[2] ?? 'ms').toLowerCase();

  switch (unit) {
    case 'us':
      return num / 1000;
    case 'ms':
      return num;
    case 's':
      return num * 1000;
    default:
      return num;
  }
}

function parseJitter(value: string): number {
  return parseLatency(value);
}

function parsePacketLoss(value: string): number {
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
}

function Slider({ label, value, config, onChange }: SliderProps) {
  return (
    <div className="lcp-slider">
      <div className="lcp-slider__header">
        <span className="lcp-slider__label">{label}</span>
        <span className="lcp-slider__value">{config.format(value)}</span>
      </div>
      <input
        type="range"
        className="lcp-slider__input"
        min={config.min}
        max={config.max}
        step={config.step}
        value={value}
        onChange={(e) => onChange(parseFloat(e.target.value))}
      />
      <div className="lcp-slider__bounds">
        <span>{config.format(config.min)}</span>
        <span>{config.format(config.max)}</span>
      </div>
    </div>
  );
}

// ============================================================================
// Main Component
// ============================================================================

// Helper to extract values from policy
function getPolicyValues(policy: TrafficPolicy | null): { bandwidth: number; latency: number; jitter: number; packetLoss: number } {
  if (policy) {
    return {
      bandwidth: parseBandwidth(policy.bandwidth),
      latency: parseLatency(policy.latency),
      jitter: parseJitter(policy.jitter),
      packetLoss: parsePacketLoss(policy.packetLoss),
    };
  }
  return { bandwidth: 10, latency: 5, jitter: 1, packetLoss: 0.1 };
}

// State type for reducer
interface SliderState {
  bandwidth: number;
  latency: number;
  jitter: number;
  packetLoss: number;
  originalValues: { bandwidth: number; latency: number; jitter: number; packetLoss: number } | null;
}

// Action types
type SliderAction =
  | { type: 'SET_BANDWIDTH'; value: number }
  | { type: 'SET_LATENCY'; value: number }
  | { type: 'SET_JITTER'; value: number }
  | { type: 'SET_PACKET_LOSS'; value: number }
  | { type: 'RESET'; values: SliderState['originalValues'] }
  | { type: 'SYNC_POLICY'; values: { bandwidth: number; latency: number; jitter: number; packetLoss: number }; hasOriginal: boolean };

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
        };
      }
      return state;
    case 'SYNC_POLICY':
      return {
        bandwidth: action.values.bandwidth,
        latency: action.values.latency,
        jitter: action.values.jitter,
        packetLoss: action.values.packetLoss,
        originalValues: action.hasOriginal ? action.values : null,
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

function LinkConfigPanel({
  linkId,
  sourceName,
  targetName,
  policy,
  onPolicyChange,
  onDelete,
  onClose,
}: LinkConfigPanelProps) {
  // Calculate initial values from policy
  const initialValues = useMemo(() => getPolicyValues(policy), [policy]);

  // Use reducer to manage all slider state
  const [state, dispatch] = useReducer(sliderReducer, {
    bandwidth: initialValues.bandwidth,
    latency: initialValues.latency,
    jitter: initialValues.jitter,
    packetLoss: initialValues.packetLoss,
    originalValues: policy ? initialValues : null,
  });

  // Track previous link id to detect changes
  const prevLinkIdRef = useRef(linkId);

  // Destructure state for easier access
  const { bandwidth, latency, jitter, packetLoss, originalValues } = state;

  // Update values when link changes (different link selected)
  useEffect(() => {
    const linkChanged = prevLinkIdRef.current !== linkId;
    
    if (linkChanged) {
      prevLinkIdRef.current = linkId;
      const newValues = getPolicyValues(policy);
      dispatch({ type: 'SYNC_POLICY', values: newValues, hasOriginal: !!policy });
    }
  }, [linkId, policy]);

  // Check for changes - derived state, no useEffect needed
  const hasChanges = checkHasChanges({ bandwidth, latency, jitter, packetLoss }, originalValues);

  // Format policy for output
  const formatPolicy = useCallback((): TrafficPolicy => {
    return {
      bandwidth:
        bandwidth >= 1000
          ? `${(bandwidth / 1000).toFixed(1)}Gbps`
          : `${bandwidth.toFixed(1)}Mbps`,
      latency: `${latency}ms`,
      jitter: `${jitter}ms`,
      packetLoss: `${packetLoss.toFixed(1)}%`,
    };
  }, [bandwidth, latency, jitter, packetLoss]);

  // Handle apply
  const handleApply = useCallback(() => {
    if (linkId && onPolicyChange) {
      onPolicyChange(linkId, formatPolicy());
      dispatch({ type: 'RESET', values: { bandwidth, latency, jitter, packetLoss } });
    }
  }, [linkId, onPolicyChange, formatPolicy, bandwidth, latency, jitter, packetLoss]);

  // Handle delete
  const handleDelete = useCallback(() => {
    if (linkId && onDelete) {
      onDelete(linkId);
    }
  }, [linkId, onDelete]);

  if (!linkId) {
    return (
      <div className="link-config-panel link-config-panel--empty">
        <div className="lcp-empty">
          <span className="lcp-empty__icon">🔗</span>
          <span className="lcp-empty__text">Select a link to configure</span>
        </div>
      </div>
    );
  }

  return (
    <div className="link-config-panel">
      <div className="lcp-header">
        <h3 className="lcp-title">Link Configuration</h3>
        {onClose && (
          <button className="lcp-close" onClick={onClose} title="Close">
            ×
          </button>
        )}
      </div>

      <div className="lcp-link-info">
        <div className="lcp-link-info__source">
          <span className="lcp-link-info__label">Source:</span>
          <span className="lcp-link-info__value">{sourceName}</span>
        </div>
        <div className="lcp-link-info__arrow">→</div>
        <div className="lcp-link-info__target">
          <span className="lcp-link-info__label">Target:</span>
          <span className="lcp-link-info__value">{targetName}</span>
        </div>
      </div>

      <div className="lcp-sliders">
        <Slider
          label="Bandwidth"
          value={bandwidth}
          config={BANDWIDTH_CONFIG}
          onChange={(value) => dispatch({ type: 'SET_BANDWIDTH', value })}
        />
        <Slider
          label="Latency"
          value={latency}
          config={LATENCY_CONFIG}
          onChange={(value) => dispatch({ type: 'SET_LATENCY', value })}
        />
        <Slider
          label="Jitter"
          value={jitter}
          config={JITTER_CONFIG}
          onChange={(value) => dispatch({ type: 'SET_JITTER', value })}
        />
        <Slider
          label="Packet Loss"
          value={packetLoss}
          config={PACKET_LOSS_CONFIG}
          onChange={(value) => dispatch({ type: 'SET_PACKET_LOSS', value })}
        />
      </div>

      <div className="lcp-preview">
        <span className="lcp-preview__label">Preview:</span>
        <code className="lcp-preview__code">
          {formatPolicy().bandwidth}, {formatPolicy().latency}, {formatPolicy().jitter},{' '}
          {formatPolicy().packetLoss}
        </code>
      </div>

      <div className="lcp-actions">
        <button className="lcp-btn lcp-btn--danger" onClick={handleDelete}>
          Delete Link
        </button>
        <button
          className="lcp-btn lcp-btn--primary"
          onClick={handleApply}
          disabled={!hasChanges}
        >
          Apply Changes
        </button>
      </div>

      {hasChanges && <div className="lcp-unsaved">You have unsaved changes</div>}
    </div>
  );
}

export default memo(LinkConfigPanel);
