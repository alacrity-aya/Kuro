/**
 * Time Range Selector Component
 * Used for Prometheus range query time range selection
 */

import './TimeRangeSelector.css';

export interface TimeRangeOption {
  value: string;
  label: string;
  description: string;
}

export const TIME_RANGE_OPTIONS: TimeRangeOption[] = [
  { value: '5m', label: '5m', description: 'Last 5 minutes' },
  { value: '15m', label: '15m', description: 'Last 15 minutes' },
  { value: '1h', label: '1h', description: 'Last 1 hour' },
  { value: '6h', label: '6h', description: 'Last 6 hours' },
  { value: '24h', label: '24h', description: 'Last 24 hours' },
  { value: '7d', label: '7d', description: 'Last 7 days' },
];

interface TimeRangeSelectorProps {
  value: string;
  onChange: (value: string) => void;
  options?: TimeRangeOption[];
  disabled?: boolean;
}

export function TimeRangeSelector({
  value,
  onChange,
  options = TIME_RANGE_OPTIONS,
  disabled = false,
}: TimeRangeSelectorProps) {
  return (
    <div className={`time-range-selector ${disabled ? 'disabled' : ''}`}>
      {options.map((option) => (
        <button
          key={option.value}
          className={`time-range-selector__btn ${value === option.value ? 'active' : ''}`}
          onClick={() => onChange(option.value)}
          disabled={disabled}
          title={option.description}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

/**
 * Calculate timestamps for time range
 */
export function calculateTimeRange(range: string): { start: number; end: number } {
  const now = Math.floor(Date.now() / 1000);
  
  const match = range.match(/^(\d+)(m|h|d)$/);
  if (!match) {
    return { start: now - 300, end: now }; // Default 5m
  }
  
  const [, value, unit] = match;
  const multipliers: Record<string, number> = { m: 60, h: 3600, d: 86400 };
  const offset = parseInt(value) * multipliers[unit];
  
  return { start: now - offset, end: now };
}

/**
 * Get recommended step value
 */
export function getRecommendedStep(range: string): string {
  switch (range) {
    case '5m':
      return '15s';
    case '15m':
      return '30s';
    case '1h':
      return '1m';
    case '6h':
      return '5m';
    case '24h':
      return '15m';
    case '7d':
      return '1h';
    default:
      return '15s';
  }
}
