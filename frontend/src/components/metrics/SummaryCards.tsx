import { useMemo } from 'react';
import type { MetricsSummary } from '../../types/api';
import './SummaryCards.css';

/**
 * Health status configuration
 */
interface HealthStatus {
  color: 'success' | 'warning' | 'danger' | 'gray';
  label: string;
  icon: string;
}

/**
 * Determine health status based on score
 */
function getHealthStatus(score: number): HealthStatus {
  if (score >= 90) {
    return { color: 'success', label: 'Healthy', icon: '✅' };
  }
  if (score >= 70) {
    return { color: 'warning', label: 'Degraded', icon: '⚠️' };
  }
  if (score >= 50) {
    return { color: 'danger', label: 'Critical', icon: '🔴' };
  }
  return { color: 'gray', label: 'Unknown', icon: '❓' };
}

/**
 * Format a number with optional decimal places
 */
function formatValue(value: number, decimals: number = 0): string {
  if (decimals === 0) {
    return Math.round(value).toString();
  }
  return value.toFixed(decimals);
}

/**
 * Props for SummaryCards component
 */
export interface SummaryCardsProps {
  /** Metrics summary data */
  data: MetricsSummary | null;
  /** Loading state */
  isLoading?: boolean;
  /** Optional CSS class name */
  className?: string;
}

/**
 * Individual card configuration
 */
interface CardConfig {
  id: string;
  icon: string;
  value: string | number;
  label: string;
  color?: 'success' | 'warning' | 'danger' | 'gray';
  subValue?: string;
}

/**
 * SummaryCards Component
 *
 * Displays a grid of summary metric cards for topology monitoring.
 * Shows nodes, links, bandwidth, latency, packet loss, and health score.
 *
 * Features:
 * - Responsive grid layout
 * - Color-coded health status
 * - Loading skeleton state
 * - Real-time value updates
 *
 * TODO: Requires backend API - GET /api/v1/metrics/summary
 */
export function SummaryCards({ data, isLoading = false, className = '' }: SummaryCardsProps) {
  // Calculate health status
  const healthStatus = useMemo(() => {
    if (!data) return getHealthStatus(0);
    return getHealthStatus(data.healthScore);
  }, [data]);

  // Build card configurations
  const cards = useMemo<CardConfig[]>(() => {
    if (!data) {
      return [];
    }

    return [
      {
        id: 'nodes',
        icon: '📦',
        value: `${data.runningNodes}/${data.totalNodes}`,
        label: 'Nodes Running',
        color: data.runningNodes === data.totalNodes ? 'success' : data.runningNodes >= data.totalNodes * 0.8 ? 'warning' : 'danger',
        subValue: data.totalNodes > 0 ? `${Math.round((data.runningNodes / data.totalNodes) * 100)}%` : undefined,
      },
      {
        id: 'links',
        icon: '🔗',
        value: `${data.activeLinks}/${data.totalLinks}`,
        label: 'Links Active',
        color: data.activeLinks === data.totalLinks ? 'success' : data.activeLinks >= data.totalLinks * 0.8 ? 'warning' : 'danger',
        subValue: data.totalLinks > 0 ? `${Math.round((data.activeLinks / data.totalLinks) * 100)}%` : undefined,
      },
      {
        id: 'bandwidth',
        icon: '📊',
        value: formatValue(data.avgBandwidthMbps, 1),
        label: 'Avg Bandwidth',
        subValue: 'Mbps',
      },
      {
        id: 'latency',
        icon: '⏱️',
        value: formatValue(data.avgLatencyMs, 1),
        label: 'Avg Latency',
        subValue: 'ms',
      },
      {
        id: 'packetLoss',
        icon: '📉',
        value: `${formatValue(data.avgPacketLoss, 2)}%`,
        label: 'Avg Packet Loss',
        color: data.avgPacketLoss < 0.5 ? 'success' : data.avgPacketLoss < 1 ? 'warning' : 'danger',
      },
      {
        id: 'health',
        icon: healthStatus.icon,
        value: `${data.healthScore}%`,
        label: healthStatus.label,
        color: healthStatus.color,
      },
    ];
  }, [data, healthStatus]);

  // Loading skeleton
  if (isLoading && !data) {
    return (
      <div className={`summary-cards ${className}`}>
        {Array.from({ length: 6 }).map((_, index) => (
          <div key={index} className="summary-card summary-card--skeleton">
            <div className="summary-card__icon skeleton" />
            <div className="summary-card__content">
              <div className="summary-card__value skeleton" />
              <div className="summary-card__label skeleton" />
            </div>
          </div>
        ))}
      </div>
    );
  }

  // No data state
  if (!data) {
    return (
      <div className={`summary-cards ${className}`}>
        <div className="summary-cards__empty">
          <span className="summary-cards__empty-icon">📊</span>
          <span className="summary-cards__empty-text">No metrics data available</span>
        </div>
      </div>
    );
  }

  return (
    <div className={`summary-cards ${className}`}>
      {cards.map((card) => (
        <div
          key={card.id}
          className={`summary-card ${card.color ? `summary-card--${card.color}` : ''}`}
        >
          <div className="summary-card__icon">{card.icon}</div>
          <div className="summary-card__content">
            <div className="summary-card__value-row">
              <span className="summary-card__value">{card.value}</span>
              {card.subValue && (
                <span className="summary-card__subvalue">{card.subValue}</span>
              )}
            </div>
            <span className="summary-card__label">{card.label}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

export default SummaryCards;
