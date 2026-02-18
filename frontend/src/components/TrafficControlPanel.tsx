import { useState, useEffect, useCallback } from 'react';
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

function parseLatency(value: string): number {
  const match = value.match(/^(\d+(?:\.\d+)?)(ms|us|s)?$/i);
  if (!match) return 0;
  
  const num = parseFloat(match[1]);
  const unit = (match[2] ?? 'ms').toLowerCase();
  
  switch (unit) {
    case 'us': return num / 1000;
    case 'ms': return num;
    case 's': return num * 1000;
    default: return num;
  }
}

function parseJitter(value: string): number {
  return parseLatency(value);
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

function TrafficControlPanel({ link, onSave, onReset, onClose }: TrafficControlPanelProps) {
  const [bandwidth, setBandwidth] = useState(10);
  const [latency, setLatency] = useState(0);
  const [jitter, setJitter] = useState(0);
  const [packetLoss, setPacketLoss] = useState(0);
  const [hasChanges, setHasChanges] = useState(false);
  const [originalValues, setOriginalValues] = useState<{
    bandwidth: number;
    latency: number;
    jitter: number;
    packetLoss: number;
  } | null>(null);

  // Initialize values from link policy
  useEffect(() => {
    if (link?.policy) {
      const bw = parseBandwidth(link.policy.bandwidth);
      const lat = parseLatency(link.policy.latency);
      const jit = parseJitter(link.policy.jitter);
      const pl = parsePacketLoss(link.policy.packetLoss);
      
      setBandwidth(bw);
      setLatency(lat);
      setJitter(jit);
      setPacketLoss(pl);
      setOriginalValues({ bandwidth: bw, latency: lat, jitter: jit, packetLoss: pl });
      setHasChanges(false);
    } else {
      // Default values for new policy
      setBandwidth(10);
      setLatency(0);
      setJitter(0);
      setPacketLoss(0);
      setOriginalValues(null);
      setHasChanges(false);
    }
  }, [link]);

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

  // Format policy for API
  const formatPolicy = useCallback((): TrafficPolicy => {
    return {
      bandwidth: bandwidth >= 1000 
        ? `${(bandwidth / 1000).toFixed(1)}Gbps` 
        : `${bandwidth.toFixed(1)}Mbps`,
      latency: `${latency}ms`,
      jitter: `${jitter}ms`,
      packetLoss: `${packetLoss.toFixed(1)}%`,
    };
  }, [bandwidth, latency, jitter, packetLoss]);

  // Handle save
  const handleSave = useCallback(() => {
    if (link && onSave) {
      onSave(link.id, formatPolicy());
      setHasChanges(false);
      setOriginalValues({ bandwidth, latency, jitter, packetLoss });
    }
  }, [link, onSave, formatPolicy, bandwidth, latency, jitter, packetLoss]);

  // Handle reset
  const handleReset = useCallback(() => {
    if (originalValues) {
      setBandwidth(originalValues.bandwidth);
      setLatency(originalValues.latency);
      setJitter(originalValues.jitter);
      setPacketLoss(originalValues.packetLoss);
      setHasChanges(false);
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
          disabled={!hasChanges && !originalValues}
        >
          Reset
        </button>
        <button
          className="tcp-btn tcp-btn--primary"
          onClick={handleSave}
          disabled={!hasChanges}
        >
          Apply Changes
        </button>
      </div>

      {hasChanges && (
        <div className="tcp-unsaved">
          You have unsaved changes
        </div>
      )}
    </div>
  );
}

export default TrafficControlPanel;
