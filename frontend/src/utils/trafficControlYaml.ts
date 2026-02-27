// frontend/src/utils/trafficControlYaml.ts

import type { TrafficControl } from '../types/api';

/**
 * Parse bandwidth string (e.g., "10Mbps", "1Gbps") to bytes per second
 */
export function parseBandwidth(value: string): number {
  const match = value.match(/^(\d+(?:\.\d+)?)(bps|Kbps|Mbps|Gbps)?$/i);
  if (!match) return 0;
  
  const num = parseFloat(match[1]);
  const unit = (match[2] || 'bps').toLowerCase();
  
  const multipliers: Record<string, number> = {
    'bps': 1,
    'kbps': 1000,
    'mbps': 1000000,
    'gbps': 1000000000,
  };
  
  return num * (multipliers[unit] || 1);
}

/**
 * Format bytes per second to human-readable bandwidth string
 */
export function formatBandwidth(bps: number): string {
  if (bps >= 1000000000) return `${(bps / 1000000000).toFixed(1)}Gbps`;
  if (bps >= 1000000) return `${(bps / 1000000).toFixed(0)}Mbps`;
  if (bps >= 1000) return `${(bps / 1000).toFixed(0)}Kbps`;
  return `${bps}bps`;
}

/**
 * Parse duration string (e.g., "50ms", "1s") to milliseconds
 */
export function parseDuration(value: string): number {
  const match = value.match(/^(\d+(?:\.\d+)?)(ms|s|m|h)?$/);
  if (!match) return 0;
  
  const num = parseFloat(match[1]);
  const unit = match[2] || 'ms';
  
  const multipliers: Record<string, number> = {
    'ms': 1,
    's': 1000,
    'm': 60000,
    'h': 3600000,
  };
  
  return num * (multipliers[unit] || 1);
}

/**
 * Format milliseconds to human-readable duration string
 */
export function formatDuration(ms: number): string {
  if (ms >= 3600000) return `${(ms / 3600000).toFixed(0)}h`;
  if (ms >= 60000) return `${(ms / 60000).toFixed(0)}m`;
  if (ms >= 1000) return `${(ms / 1000).toFixed(0)}s`;
  return `${ms}ms`;
}

/**
 * Parse percentage string (e.g., "0.5%", "1%") to decimal
 */
export function parsePercentage(value: string): number {
  const match = value.match(/^(\d+(?:\.\d+)?)%$/);
  if (!match) return 0;
  return parseFloat(match[1]) / 100;
}

/**
 * Format decimal to percentage string
 */
export function formatPercentage(decimal: number): string {
  return `${(decimal * 100).toFixed(2)}%`;
}

/**
 * Export TrafficControl to YAML string
 */
export function exportTrafficControlToYaml(tc: TrafficControl): string {
  const policy = tc.spec.policy;
  
  return `apiVersion: simulation.kuro.io/v1alpha1
kind: TrafficControl
metadata:
  name: ${tc.metadata.name}
  namespace: ${tc.metadata.namespace}
spec:
  source:
    matchLabels:
      role: ${tc.spec.source.matchLabels['role'] || ''}
  destination:
    matchLabels:
      role: ${tc.spec.destination.matchLabels['role'] || ''}
  policy:
    bandwidth: ${policy.bandwidth || ''}
    latency: ${policy.latency || ''}
    jitter: ${policy.jitter || ''}
    packetLoss: ${policy.packetLoss || ''}
`;
}

/**
 * Parse YAML string to TrafficControl object
 */
export function parseTrafficControlYaml(yaml: string): Partial<TrafficControl> {
  const lines = yaml.split('\n').map(l => l.trim()).filter(l => l);
  const result: Partial<TrafficControl> = {
    apiVersion: 'simulation.kuro.io/v1alpha1',
    kind: 'TrafficControl',
    metadata: { name: '', namespace: 'default', uid: '', creationTimestamp: '' },
    spec: {
      source: { matchLabels: {} },
      destination: { matchLabels: {} },
      policy: { bandwidth: '', latency: '', jitter: '', packetLoss: '' },
    },
  };
  
  let currentSection = '';
  let currentMatchLabels: 'source' | 'destination' | null = null;
  
  for (const line of lines) {
    // Skip comments
    if (line.startsWith('#')) continue;
    
    // Top-level sections
    if (line.startsWith('name:') && currentSection === 'metadata') {
      result.metadata!.name = line.split(':')[1].trim();
    } else if (line.startsWith('namespace:') && currentSection === 'metadata') {
      result.metadata!.namespace = line.split(':')[1].trim();
    } else if (line.startsWith('role:') && currentMatchLabels) {
      const role = line.split(':')[1].trim();
      if (currentMatchLabels === 'source') {
        result.spec!.source.matchLabels['role'] = role;
      } else {
        result.spec!.destination.matchLabels['role'] = role;
      }
    } else if (line.startsWith('bandwidth:') && currentSection === 'policy') {
      result.spec!.policy!.bandwidth = line.split(':')[1].trim();
    } else if (line.startsWith('latency:') && currentSection === 'policy') {
      result.spec!.policy!.latency = line.split(':')[1].trim();
    } else if (line.startsWith('jitter:') && currentSection === 'policy') {
      result.spec!.policy!.jitter = line.split(':')[1].trim();
    } else if (line.startsWith('packetLoss:') && currentSection === 'policy') {
      result.spec!.policy!.packetLoss = line.split(':')[1].trim();
    }
    
    // Track current section
    if (line === 'metadata:') currentSection = 'metadata';
    else if (line === 'spec:') currentSection = 'spec';
    else if (line === 'source:') currentMatchLabels = 'source';
    else if (line === 'destination:') currentMatchLabels = 'destination';
    else if (line === 'matchLabels:') { /* nested under source/destination */ }
    else if (line === 'policy:') currentSection = 'policy';
  }
  
  return result;
}

/**
 * Validate TrafficControl YAML
 */
export function validateTrafficControlYaml(yaml: string): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  try {
    const tc = parseTrafficControlYaml(yaml);
    
    if (!tc.metadata?.name) {
      errors.push('Missing metadata.name');
    }
    if (!tc.spec?.source?.matchLabels?.['role']) {
      errors.push('Missing spec.source.matchLabels.role');
    }
    if (!tc.spec?.destination?.matchLabels?.['role']) {
      errors.push('Missing spec.destination.matchLabels.role');
    }
    
    return { valid: errors.length === 0, errors };
  } catch (e) {
    return { valid: false, errors: [`Failed to parse YAML: ${e}`] };
  }
}

/**
 * Download YAML file
 */
export function downloadYaml(content: string, filename: string): void {
  const blob = new Blob([content], { type: 'text/yaml' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
