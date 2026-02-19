import { useState, useEffect, useCallback, memo } from 'react';
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

function LinkConfigPanel({
  linkId,
  sourceName,
  targetName,
  policy,
  onPolicyChange,
  onDelete,
  onClose,
}: LinkConfigPanelProps) {
  const [bandwidth, setBandwidth] = useState(10);
  const [latency, setLatency] = useState(5);
  const [jitter, setJitter] = useState(1);
  const [packetLoss, setPacketLoss] = useState(0.1);
  const [hasChanges, setHasChanges] = useState(false);
  const [originalValues, setOriginalValues] = useState<{
    bandwidth: number;
    latency: number;
    jitter: number;
    packetLoss: number;
  } | null>(null);

  // Initialize values from policy
  useEffect(() => {
    if (policy) {
      const bw = parseBandwidth(policy.bandwidth);
      const lat = parseLatency(policy.latency);
      const jit = parseJitter(policy.jitter);
      const pl = parsePacketLoss(policy.packetLoss);

      setBandwidth(bw);
      setLatency(lat);
      setJitter(jit);
      setPacketLoss(pl);
      setOriginalValues({ bandwidth: bw, latency: lat, jitter: jit, packetLoss: pl });
      setHasChanges(false);
    } else {
      // Default values for new link
      setBandwidth(10);
      setLatency(5);
      setJitter(1);
      setPacketLoss(0.1);
      setOriginalValues(null);
      setHasChanges(false);
    }
  }, [policy]);

  // Check for changes
  useEffect(() => {
    if (originalValues) {
      const changed =
        bandwidth !== originalValues.bandwidth ||
        latency !== originalValues.latency ||
        jitter !== originalValues.jitter ||
        packetLoss !== originalValues.packetLoss;
      setHasChanges(changed);
    }
  }, [bandwidth, latency, jitter, packetLoss, originalValues]);

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
      setHasChanges(false);
      setOriginalValues({ bandwidth, latency, jitter, packetLoss });
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
          onChange={setBandwidth}
        />
        <Slider
          label="Latency"
          value={latency}
          config={LATENCY_CONFIG}
          onChange={setLatency}
        />
        <Slider
          label="Jitter"
          value={jitter}
          config={JITTER_CONFIG}
          onChange={setJitter}
        />
        <Slider
          label="Packet Loss"
          value={packetLoss}
          config={PACKET_LOSS_CONFIG}
          onChange={setPacketLoss}
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
