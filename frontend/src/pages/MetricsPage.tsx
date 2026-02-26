/**
 * Metrics Page - Grafana Integration
 * 
 * Embeds full Grafana dashboard with all native features:
 * - Dashboard switching
 * - Time range selection
 * - Variable filters
 * - Explore (PromQL queries)
 * - Fullscreen mode
 */

import { GrafanaEmbed } from '../components/metrics/GrafanaEmbed';
import './MetricsPage.css';

export default function MetricsPage() {
  // Get Grafana URL from environment
  const grafanaUrl = import.meta.env.VITE_GRAFANA_URL || 'http://localhost:30092';

  return (
    <div className="metrics-page">
      {/* Minimal Header */}
      <div className="metrics-page__header">
        <h1 className="metrics-page__title">Network Metrics</h1>
        {grafanaUrl && (
          <a
            href={grafanaUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="metrics-page__grafana-link"
          >
            <span className="metrics-page__grafana-icon">📊</span>
            Open Grafana
          </a>
        )}
      </div>

      {/* Full Grafana iframe */}
      <div className="metrics-page__grafana-container">
        <GrafanaEmbed
          dashboardUid="kuro-network-metrics"
          theme="dark"
          height={800}
          showFullscreenButton={false}
          showRefreshControls={false}
          title="Kuro Network Dashboard"
        />
      </div>
    </div>
  );
}
