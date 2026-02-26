/**
 * Grafana Embed Component
 * 
 * Embeds Grafana dashboard iframe, supports:
 * - Full dashboard embed
 * - Single panel embed
 * - Fullscreen toggle
 * - Auto refresh
 * 
 * TODO: Requires VITE_GRAFANA_URL environment variable configuration
 * TODO: Requires backend API - Grafana Service (NodePort 30092)
 */

import { useState, useMemo, useCallback } from 'react';
import './GrafanaEmbed.css';

// ============================================================================
// Types
// ============================================================================

export interface GrafanaEmbedProps {
  /** Grafana dashboard UID */
  dashboardUid: string;
  /** Panel ID for single panel embed (optional) */
  panelId?: number;
  /** Refresh interval (default: '5s') */
  refresh?: string;
  /** Theme (default: 'dark') */
  theme?: 'dark' | 'light';
  /** Height in pixels (default: 600) */
  height?: number;
  /** Show fullscreen button (default: true) */
  showFullscreenButton?: boolean;
  /** Show refresh controls (default: true) */
  showRefreshControls?: boolean;
  /** Panel title override */
  title?: string;
  /** Additional URL parameters */
  params?: Record<string, string>;
  /** Called when iframe loads */
  onLoad?: () => void;
  /** Called when iframe fails to load */
  onError?: (error: Error) => void;
}

interface RefreshOption {
  value: string;
  label: string;
}

const REFRESH_OPTIONS: RefreshOption[] = [
  { value: '5s', label: '5s' },
  { value: '10s', label: '10s' },
  { value: '30s', label: '30s' },
  { value: '1m', label: '1m' },
  { value: '5m', label: '5m' },
  { value: '0', label: 'Off' },
];

// ============================================================================
// Component
// ============================================================================

export function GrafanaEmbed({
  dashboardUid,
  panelId,
  refresh = '5s',
  theme = 'dark',
  height = 600,
  showFullscreenButton = true,
  showRefreshControls = true,
  title,
  params,
  onLoad,
  onError,
}: GrafanaEmbedProps) {
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [currentRefresh, setCurrentRefresh] = useState(refresh);
  const [isLoading, setIsLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [iframeKey, setIframeKey] = useState(0);

  // Get Grafana URL from environment or default
  const grafanaUrl = useMemo(() => {
    return import.meta.env.VITE_GRAFANA_URL || 'http://localhost:30092';
  }, []);

  // Build iframe URL
  const iframeUrl = useMemo(() => {
    // Full mode - no kiosk, shows complete Grafana UI
    const embedPath = panelId
      ? `/d-solo/${dashboardUid}`
      : `/d/${dashboardUid}`;

    const searchParams = new URLSearchParams({
      orgId: '1',
      theme,
      ...(currentRefresh !== '0' && { refresh: currentRefresh }),
      ...(panelId && { panelId: panelId.toString() }),
      ...(params || {}),
    });

    return `${grafanaUrl}${embedPath}?${searchParams.toString()}`;
  }, [grafanaUrl, dashboardUid, panelId, currentRefresh, theme, params]);

  // Handle fullscreen toggle
  const toggleFullscreen = useCallback(() => {
    setIsFullscreen(prev => !prev);
  }, []);

  // Handle refresh change
  const handleRefreshChange = useCallback((newRefresh: string) => {
    setCurrentRefresh(newRefresh);
    // Force iframe reload to apply new refresh interval
    setIframeKey(prev => prev + 1);
  }, []);

  // Handle manual refresh
  const handleManualRefresh = useCallback(() => {
    setIframeKey(prev => prev + 1);
  }, []);

  // Handle iframe load
  const handleIframeLoad = useCallback(() => {
    setIsLoading(false);
    setLoadError(null);
    onLoad?.();
  }, [onLoad]);

  // Handle iframe error
  const handleIframeError = useCallback(() => {
    setIsLoading(false);
    const error = new Error('Failed to load Grafana dashboard');
    setLoadError(error.message);
    onError?.(error);
  }, [onError]);

  // Exit fullscreen on Escape key
  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Escape' && isFullscreen) {
      setIsFullscreen(false);
    }
  }, [isFullscreen]);

  return (
    <div
      className={`grafana-embed ${isFullscreen ? 'grafana-embed--fullscreen' : ''}`}
      style={{ height: isFullscreen ? '100vh' : height }}
      onKeyDown={handleKeyDown}
    >
      {/* Toolbar */}
      <div className="grafana-embed__toolbar">
        <div className="grafana-embed__toolbar-left">
          <span className="grafana-embed__title">
            {title || (panelId ? 'Grafana Panel' : 'Grafana Dashboard')}
          </span>
          
          {/* Loading indicator */}
          {isLoading && (
            <span className="grafana-embed__loading">Loading...</span>
          )}
          
          {/* Error indicator */}
          {loadError && (
            <span className="grafana-embed__error">{loadError}</span>
          )}
        </div>

        <div className="grafana-embed__toolbar-right">
          {/* Refresh controls */}
          {showRefreshControls && (
            <div className="grafana-embed__refresh">
              <select
                className="grafana-embed__refresh-select"
                value={currentRefresh}
                onChange={(e) => handleRefreshChange(e.target.value)}
                title="Refresh interval"
              >
                {REFRESH_OPTIONS.map(option => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
              
              <button
                className="grafana-embed__refresh-btn"
                onClick={handleManualRefresh}
                title="Refresh now"
              >
                ⟳
              </button>
            </div>
          )}

          {/* Fullscreen button */}
          {showFullscreenButton && (
            <button
              className="grafana-embed__fullscreen-btn"
              onClick={toggleFullscreen}
              title={isFullscreen ? 'Exit fullscreen' : 'Fullscreen'}
            >
              {isFullscreen ? '✕' : '⛶'}
            </button>
          )}

          {/* Open in Grafana */}
          <a
            className="grafana-embed__external-link"
            href={`${grafanaUrl}/d/${dashboardUid}`}
            target="_blank"
            rel="noopener noreferrer"
            title="Open in Grafana"
          >
            ↗
          </a>
        </div>
      </div>

      {/* iframe container */}
      <div className="grafana-embed__content">
        {loadError ? (
          <div className="grafana-embed__error-state">
            <div className="grafana-embed__error-icon">⚠️</div>
            <div className="grafana-embed__error-message">
              <p>Failed to load Grafana dashboard</p>
              <p className="grafana-embed__error-detail">
                Make sure Grafana is running at: <code>{grafanaUrl}</code>
              </p>
              <button
                className="grafana-embed__retry-btn"
                onClick={handleManualRefresh}
              >
                Retry
              </button>
            </div>
          </div>
        ) : (
          <iframe
            key={iframeKey}
            className="grafana-embed__iframe"
            src={iframeUrl}
            width="100%"
            height="100%"
            frameBorder="0"
            title={title || 'Grafana Dashboard'}
            onLoad={handleIframeLoad}
            onError={handleIframeError}
            allow="fullscreen"
          />
        )}
      </div>
    </div>
  );
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Check if Grafana is reachable
 */
export async function checkGrafanaHealth(grafanaUrl?: string): Promise<boolean> {
  const url = grafanaUrl || import.meta.env.VITE_GRAFANA_URL || 'http://localhost:30092';
  
  try {
    const response = await fetch(`${url}/api/health`, {
      method: 'GET',
      mode: 'cors',
    });
    return response.ok;
  } catch {
    return false;
  }
}

/**
 * Get list of available dashboards from Grafana
 * Requires Grafana API authentication
 */
export async function getGrafanaDashboards(
  grafanaUrl?: string,
  apiKey?: string
): Promise<Array<{ uid: string; title: string }>> {
  const url = grafanaUrl || import.meta.env.VITE_GRAFANA_URL || 'http://localhost:30092';
  
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  
  if (apiKey) {
    headers['Authorization'] = `Bearer ${apiKey}`;
  }
  
  try {
    const response = await fetch(`${url}/api/search?type=dash-db`, {
      method: 'GET',
      headers,
    });
    
    if (!response.ok) {
      throw new Error('Failed to fetch dashboards');
    }
    
    const dashboards = await response.json();
    return dashboards.map((d: { uid: string; title: string }) => ({
      uid: d.uid,
      title: d.title,
    }));
  } catch {
    return [];
  }
}

export default GrafanaEmbed;
