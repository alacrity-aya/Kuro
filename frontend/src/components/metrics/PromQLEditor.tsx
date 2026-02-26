/**
 * PromQL Editor Component
 * 
 * Provides a PromQL query editor with:
 * - Syntax highlighting input
 * - Query execution
 * - Results display (table/graph)
 * - Query history
 * - Common query templates
 */

import { useState, useCallback, useMemo, useRef, useEffect } from 'react';
import type { InstantVector, RangeVector } from '../../api/prometheus';
import './PromQLEditor.css';

// ============================================================================
// Types
// ============================================================================

export interface PromQLEditorProps {
  /** Initial query */
  initialQuery?: string;
  /** Time range for range queries */
  timeRange?: string;
  /** Callback when query is executed */
  onQuery?: (query: string) => void;
  /** Prometheus API base URL */
  prometheusUrl?: string;
  /** Height of the results area */
  height?: number;
}

interface QueryResult {
  type: 'instant' | 'range';
  data: InstantVector[] | RangeVector[];
  executedAt: Date;
}

interface QueryTemplate {
  name: string;
  description: string;
  query: string;
}

// ============================================================================
// Query Templates
// ============================================================================

const QUERY_TEMPLATES: QueryTemplate[] = [
  {
    name: 'Pod Traffic',
    description: 'Total traffic bytes per pod',
    query: 'sum(kuro_pod_traffic_bytes_total) by (pod)',
  },
  {
    name: 'Bandwidth Rate',
    description: 'Current bandwidth per pod',
    query: 'sum(rate(kuro_pod_traffic_bytes_total[1m])) by (pod, type, direction)',
  },
  {
    name: 'Sim Upload Bandwidth',
    description: 'Simulation upload bandwidth',
    query: 'sum(rate(kuro_pod_traffic_bytes_total{type="sim", direction="upload"}[1m])) by (pod)',
  },
  {
    name: 'Packet Loss Rate',
    description: 'Packet loss percentage',
    query: 'sum(rate(kuro_pod_drop_packets_total[1m])) / sum(rate(kuro_pod_traffic_packets_total[1m])) * 100',
  },
  {
    name: 'Latency P95',
    description: '95th percentile latency',
    query: 'histogram_quantile(0.95, sum(rate(kuro_pod_latency_seconds_bucket[5m])) by (le))',
  },
  {
    name: 'Active Pods',
    description: 'Count of pods with traffic',
    query: 'count(count by (pod) (kuro_pod_traffic_bytes_total))',
  },
];

// ============================================================================
// Component
// ============================================================================

export function PromQLEditor({
  initialQuery = '',
  timeRange = '15m',
  onQuery,
  prometheusUrl,
  height = 400,
}: PromQLEditorProps) {
  const [query, setQuery] = useState(initialQuery);
  const [isExecuting, setIsExecuting] = useState(false);
  const [result, setResult] = useState<QueryResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [queryHistory, setQueryHistory] = useState<string[]>([]);
  const [showTemplates, setShowTemplates] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  const [viewMode, setViewMode] = useState<'table' | 'graph'>('table');
  const inputRef = useRef<HTMLTextAreaElement>(null);

  // Get Prometheus URL
  const baseUrl = useMemo(() => {
    return prometheusUrl || import.meta.env.VITE_PROMETHEUS_URL || 'http://localhost:30091';
  }, [prometheusUrl]);

  // Load history from localStorage
  useEffect(() => {
    const saved = localStorage.getItem('promql-history');
    if (saved) {
      try {
        setQueryHistory(JSON.parse(saved).slice(0, 20));
      } catch {
        // Ignore parse errors
      }
    }
  }, []);

  // Save history to localStorage
  const saveToHistory = useCallback((q: string) => {
    setQueryHistory(prev => {
      const filtered = prev.filter(h => h !== q);
      const updated = [q, ...filtered].slice(0, 20);
      localStorage.setItem('promql-history', JSON.stringify(updated));
      return updated;
    });
  }, []);

  // Execute query
  const executeQuery = useCallback(async () => {
    if (!query.trim()) return;

    setIsExecuting(true);
    setError(null);
    setResult(null);

    try {
      const end = Date.now() / 1000;
      const start = end - parseTimeRange(timeRange);
      
      // Try range query first
      const rangeUrl = `${baseUrl}/api/v1/query_range?query=${encodeURIComponent(query)}&start=${start}&end=${end}&step=15`;
      
      const response = await fetch(rangeUrl);
      const data = await response.json();

      if (data.status === 'error') {
        throw new Error(data.error || 'Query failed');
      }

      if (data.data?.resultType === 'matrix') {
        setResult({
          type: 'range',
          data: data.data.result as RangeVector[],
          executedAt: new Date(),
        });
      } else if (data.data?.resultType === 'vector') {
        setResult({
          type: 'instant',
          data: data.data.result as InstantVector[],
          executedAt: new Date(),
        });
      }

      saveToHistory(query.trim());
      onQuery?.(query.trim());
    } catch (err) {
      // Try instant query as fallback
      try {
        const instantUrl = `${baseUrl}/api/v1/query?query=${encodeURIComponent(query)}`;
        const response = await fetch(instantUrl);
        const data = await response.json();

        if (data.status === 'error') {
          throw new Error(data.error || 'Query failed');
        }

        setResult({
          type: 'instant',
          data: data.data.result as InstantVector[],
          executedAt: new Date(),
        });

        saveToHistory(query.trim());
        onQuery?.(query.trim());
      } catch (fallbackErr) {
        setError(fallbackErr instanceof Error ? fallbackErr.message : 'Query failed');
      }
    } finally {
      setIsExecuting(false);
    }
  }, [query, baseUrl, timeRange, saveToHistory, onQuery]);

  // Handle keyboard shortcuts
  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      executeQuery();
    }
  }, [executeQuery]);

  // Use template
  const useTemplate = useCallback((template: QueryTemplate) => {
    setQuery(template.query);
    setShowTemplates(false);
    inputRef.current?.focus();
  }, []);

  // Use history item
  const useHistoryItem = useCallback((item: string) => {
    setQuery(item);
    setShowHistory(false);
    inputRef.current?.focus();
  }, []);

  return (
    <div className="promql-editor" style={{ height }}>
      {/* Query Input */}
      <div className="promql-editor__input-section">
        <div className="promql-editor__toolbar">
          <button
            className="promql-editor__toolbar-btn"
            onClick={() => setShowTemplates(!showTemplates)}
            title="Query Templates"
          >
            📋 Templates
          </button>
          <button
            className="promql-editor__toolbar-btn"
            onClick={() => setShowHistory(!showHistory)}
            title="Query History"
          >
            📜 History ({queryHistory.length})
          </button>
          <div className="promql-editor__toolbar-spacer" />
          <span className="promql-editor__hint">
            Ctrl+Enter to execute
          </span>
        </div>

        {/* Templates Dropdown */}
        {showTemplates && (
          <div className="promql-editor__dropdown">
            {QUERY_TEMPLATES.map((template, index) => (
              <button
                key={index}
                className="promql-editor__template-item"
                onClick={() => useTemplate(template)}
              >
                <span className="promql-editor__template-name">{template.name}</span>
                <span className="promql-editor__template-desc">{template.description}</span>
                <code className="promql-editor__template-query">{template.query}</code>
              </button>
            ))}
          </div>
        )}

        {/* History Dropdown */}
        {showHistory && queryHistory.length > 0 && (
          <div className="promql-editor__dropdown">
            {queryHistory.map((item, index) => (
              <button
                key={index}
                className="promql-editor__history-item"
                onClick={() => useHistoryItem(item)}
              >
                <code>{item}</code>
              </button>
            ))}
          </div>
        )}

        <div className="promql-editor__input-row">
          <textarea
            ref={inputRef}
            className="promql-editor__input"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Enter PromQL query... e.g., kuro_pod_traffic_bytes_total"
            rows={2}
            spellCheck={false}
          />
          <button
            className="promql-editor__execute-btn"
            onClick={executeQuery}
            disabled={isExecuting || !query.trim()}
          >
            {isExecuting ? '⏳' : '▶'} Execute
          </button>
        </div>
      </div>

      {/* Results */}
      <div className="promql-editor__results">
        {/* Error */}
        {error && (
          <div className="promql-editor__error">
            <span className="promql-editor__error-icon">⚠️</span>
            <span>{error}</span>
          </div>
        )}

        {/* Results Header */}
        {result && (
          <div className="promql-editor__results-header">
            <span className="promql-editor__results-info">
              {result.type === 'range' ? 'Range Query' : 'Instant Query'} • 
              {result.data.length} series • 
              {result.executedAt.toLocaleTimeString()}
            </span>
            <div className="promql-editor__view-toggle">
              <button
                className={`promql-editor__view-btn ${viewMode === 'table' ? 'promql-editor__view-btn--active' : ''}`}
                onClick={() => setViewMode('table')}
              >
                Table
              </button>
              <button
                className={`promql-editor__view-btn ${viewMode === 'graph' ? 'promql-editor__view-btn--active' : ''}`}
                onClick={() => setViewMode('graph')}
              >
                Graph
              </button>
            </div>
          </div>
        )}

        {/* Results Content */}
        {result && result.data.length > 0 && (
          <div className="promql-editor__results-content">
            {viewMode === 'table' ? (
              <ResultTable result={result} />
            ) : (
              <ResultGraph result={result} />
            )}
          </div>
        )}

        {/* Empty State */}
        {result && result.data.length === 0 && (
          <div className="promql-editor__empty">
            No data returned
          </div>
        )}
      </div>
    </div>
  );
}

// ============================================================================
// Result Table Component
// ============================================================================

interface ResultTableProps {
  result: QueryResult;
}

function ResultTable({ result }: ResultTableProps) {
  if (result.type === 'instant') {
    return (
      <div className="promql-result-table">
        <table>
          <thead>
            <tr>
              <th>Labels</th>
              <th>Value</th>
            </tr>
          </thead>
          <tbody>
            {(result.data as InstantVector[]).map((vector, index) => (
              <tr key={index}>
                <td className="promql-result-table__labels">
                  {Object.entries(vector.metric)
                    .filter(([k]) => k !== '__name__')
                    .map(([k, v]) => (
                      <span key={k} className="promql-result-table__label">
                        <span className="promql-result-table__label-key">{k}</span>=
                        <span className="promql-result-table__label-value">"{v}"</span>
                      </span>
                    ))}
                </td>
                <td className="promql-result-table__value">
                  {formatValue(vector.value[1])}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  // Range query - show first and last values
  return (
    <div className="promql-result-table">
      <table>
        <thead>
          <tr>
            <th>Labels</th>
            <th>First Value</th>
            <th>Last Value</th>
            <th>Samples</th>
          </tr>
        </thead>
        <tbody>
          {(result.data as RangeVector[]).map((vector, index) => (
            <tr key={index}>
              <td className="promql-result-table__labels">
                {Object.entries(vector.metric)
                  .filter(([k]) => k !== '__name__')
                  .map(([k, v]) => (
                    <span key={k} className="promql-result-table__label">
                      <span className="promql-result-table__label-key">{k}</span>=
                      <span className="promql-result-table__label-value">"{v}"</span>
                    </span>
                  ))}
              </td>
              <td className="promql-result-table__value">
                {vector.values.length > 0 ? formatValue(vector.values[0][1]) : '-'}
              </td>
              <td className="promql-result-table__value">
                {vector.values.length > 0 ? formatValue(vector.values[vector.values.length - 1][1]) : '-'}
              </td>
              <td className="promql-result-table__count">
                {vector.values.length}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ============================================================================
// Result Graph Component (Simple SVG)
// ============================================================================

function ResultGraph({ result }: ResultTableProps) {
  if (result.type === 'instant') {
    return (
      <div className="promql-result-graph promql-result-graph--instant">
        <div className="promql-result-graph__bars">
          {(result.data as InstantVector[]).map((vector, index) => {
            const value = parseFloat(vector.value[1]);
            const label = vector.metric.pod || vector.metric.instance || `series-${index}`;
            const maxValue = Math.max(...(result.data as InstantVector[]).map(v => parseFloat(v.value[1])));
            const percentage = maxValue > 0 ? (value / maxValue) * 100 : 0;
            
            return (
              <div key={index} className="promql-result-graph__bar-item">
                <div 
                  className="promql-result-graph__bar" 
                  style={{ width: `${percentage}%` }}
                />
                <span className="promql-result-graph__bar-label">{label}</span>
                <span className="promql-result-graph__bar-value">{formatValue(vector.value[1])}</span>
              </div>
            );
          })}
        </div>
      </div>
    );
  }

  // Range query - simple line chart placeholder
  return (
    <div className="promql-result-graph promql-result-graph--range">
      <div className="promql-result-graph__placeholder">
        📈 Range data visualization - {result.data.length} series
        <br />
        <small>Use Table view for detailed data</small>
      </div>
    </div>
  );
}

// ============================================================================
// Helper Functions
// ============================================================================

function parseTimeRange(range: string): number {
  const match = range.match(/^(\d+)([smhd])$/);
  if (!match) return 900; // Default 15m
  
  const value = parseInt(match[1], 10);
  const unit = match[2];
  
  switch (unit) {
    case 's': return value;
    case 'm': return value * 60;
    case 'h': return value * 3600;
    case 'd': return value * 86400;
    default: return 900;
  }
}

function formatValue(value: string | number): string {
  const num = typeof value === 'string' ? parseFloat(value) : value;
  if (isNaN(num)) return String(value);
  
  if (Math.abs(num) >= 1e9) return (num / 1e9).toFixed(2) + 'G';
  if (Math.abs(num) >= 1e6) return (num / 1e6).toFixed(2) + 'M';
  if (Math.abs(num) >= 1e3) return (num / 1e3).toFixed(2) + 'K';
  if (Math.abs(num) < 0.01 && num !== 0) return num.toExponential(2);
  return num.toFixed(2);
}

export default PromQLEditor;
