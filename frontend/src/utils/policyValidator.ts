/**
 * Traffic Policy Validation Utilities
 *
 * Validates policy values for TrafficControl CRDs including:
 * - Bandwidth: number + unit (bps, Kbps, Mbps, Gbps)
 * - Latency: number + unit (ms, s)
 * - Jitter: number + unit (ms, s)
 * - Packet Loss: percentage (0-100%)
 */

export interface PolicyValidationResult {
  isValid: boolean;
  errors: Record<string, string>;
}

// Bandwidth: number + unit (bps, Kbps, Mbps, Gbps)
const BANDWIDTH_REGEX = /^(\d+(?:\.\d+)?)\s*(bps|Kbps|Mbps|Gbps)$/i;

// Latency/Jitter: number + unit (ms, s)
const LATENCY_REGEX = /^(\d+(?:\.\d+)?)\s*(ms|s)$/i;

// Packet Loss: percentage (0-100%)
const PACKET_LOSS_REGEX = /^(\d+(?:\.\d+)?)\s*%$/;

/**
 * Validate bandwidth format
 * @param value - Bandwidth string (e.g., "10Mbps", "1Gbps")
 * @returns Error message or null if valid
 */
export function validateBandwidth(value: string): string | null {
  if (!value.trim()) return 'Bandwidth is required';
  if (!BANDWIDTH_REGEX.test(value)) {
    return 'Invalid format. Use: 10Mbps, 1Gbps, 100Kbps, 500bps';
  }
  return null;
}

/**
 * Validate latency format
 * @param value - Latency string (e.g., "10ms", "1s")
 * @returns Error message or null if valid
 */
export function validateLatency(value: string): string | null {
  if (!value.trim()) return 'Latency is required';
  if (!LATENCY_REGEX.test(value)) {
    return 'Invalid format. Use: 10ms, 1s, 500ms';
  }
  return null;
}

/**
 * Validate jitter format
 * @param value - Jitter string (e.g., "5ms", "0.5s")
 * @returns Error message or null if valid
 */
export function validateJitter(value: string): string | null {
  if (!value.trim()) return 'Jitter is required';
  if (!LATENCY_REGEX.test(value)) {
    return 'Invalid format. Use: 5ms, 0.5s, 10ms';
  }
  return null;
}

/**
 * Validate packet loss format and range
 * @param value - Packet loss string (e.g., "0.1%", "1%")
 * @returns Error message or null if valid
 */
export function validatePacketLoss(value: string): string | null {
  if (!value.trim()) return 'Packet loss is required';
  const match = value.match(PACKET_LOSS_REGEX);
  if (!match) {
    return 'Invalid format. Use: 0.1%, 1%, 50%';
  }
  const num = parseFloat(match[1]);
  if (num < 0 || num > 100) {
    return 'Packet loss must be between 0% and 100%';
  }
  return null;
}

/**
 * Validate all policy fields
 * @param policy - Policy object with bandwidth, latency, jitter, packetLoss
 * @returns Validation result with isValid flag and errors object
 */
export function validatePolicy(policy: {
  bandwidth: string;
  latency: string;
  jitter: string;
  packetLoss: string;
}): PolicyValidationResult {
  const errors: Record<string, string> = {};

  const bandwidthError = validateBandwidth(policy.bandwidth);
  if (bandwidthError) errors.bandwidth = bandwidthError;

  const latencyError = validateLatency(policy.latency);
  if (latencyError) errors.latency = latencyError;

  const jitterError = validateJitter(policy.jitter);
  if (jitterError) errors.jitter = jitterError;

  const packetLossError = validatePacketLoss(policy.packetLoss);
  if (packetLossError) errors.packetLoss = packetLossError;

  return {
    isValid: Object.keys(errors).length === 0,
    errors,
  };
}

/**
 * Parse bandwidth value to bits per second
 * @param value - Bandwidth string (e.g., "10Mbps")
 * @returns Bandwidth in bps or null if invalid
 */
export function parseBandwidth(value: string): number | null {
  const match = value.match(BANDWIDTH_REGEX);
  if (!match) return null;

  const num = parseFloat(match[1]);
  const unit = match[2].toLowerCase();

  switch (unit) {
    case 'bps':
      return num;
    case 'kbps':
      return num * 1000;
    case 'mbps':
      return num * 1000000;
    case 'gbps':
      return num * 1000000000;
    default:
      return null;
  }
}

/**
 * Parse latency/jitter value to milliseconds
 * @param value - Latency string (e.g., "10ms", "1s")
 * @returns Latency in milliseconds or null if invalid
 */
export function parseLatency(value: string): number | null {
  const match = value.match(LATENCY_REGEX);
  if (!match) return null;

  const num = parseFloat(match[1]);
  const unit = match[2].toLowerCase();

  switch (unit) {
    case 'ms':
      return num;
    case 's':
      return num * 1000;
    default:
      return null;
  }
}

/**
 * Parse packet loss value to percentage number
 * @param value - Packet loss string (e.g., "0.1%")
 * @returns Packet loss percentage or null if invalid
 */
export function parsePacketLoss(value: string): number | null {
  const match = value.match(PACKET_LOSS_REGEX);
  if (!match) return null;

  return parseFloat(match[1]);
}
