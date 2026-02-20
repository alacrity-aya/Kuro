/**
 * Auto Refresh Hook
 * Used to control dashboard auto-refresh interval
 */

import { useState, useEffect, useCallback, useRef } from 'react';

export interface RefreshInterval {
  value: number;  // milliseconds
  label: string;
}

export const REFRESH_INTERVALS: RefreshInterval[] = [
  { value: 5000, label: '5s' },
  { value: 10000, label: '10s' },
  { value: 30000, label: '30s' },
  { value: 60000, label: '1m' },
  { value: 300000, label: '5m' },
];

export interface UseAutoRefreshOptions {
  /** Initial refresh interval (ms), default 5000 */
  initialInterval?: number;
  /** Whether to initially enable auto-refresh, default true */
  initialEnabled?: boolean;
  /** Refresh callback function */
  onRefresh: () => void | Promise<void>;
}

export interface UseAutoRefreshReturn {
  /** Current refresh interval */
  interval: number;
  /** Set refresh interval */
  setInterval: (ms: number) => void;
  /** Whether auto-refresh is enabled */
  enabled: boolean;
  /** Set enabled state */
  setEnabled: (enabled: boolean) => void;
  /** Manually trigger refresh */
  refresh: () => void;
  /** Last refresh time */
  lastRefreshTime: Date | null;
  /** Is refreshing */
  isRefreshing: boolean;
  /** Refresh count */
  refreshCount: number;
}

/**
 * Auto Refresh Hook
 *
 * @example
 * ```tsx
 * const { enabled, setEnabled, interval, setInterval, refresh, isRefreshing } = useAutoRefresh({
 *   onRefresh: async () => {
 *     const data = await fetchData();
 *     setData(data);
 *   },
 *   initialInterval: 10000,
 * });
 * ```
 */
export function useAutoRefresh({
  initialInterval = 5000,
  initialEnabled = true,
  onRefresh,
}: UseAutoRefreshOptions): UseAutoRefreshReturn {
  const [interval, setIntervalState] = useState(initialInterval);
  const [enabled, setEnabled] = useState(initialEnabled);
  const [lastRefreshTime, setLastRefreshTime] = useState<Date | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [refreshCount, setRefreshCount] = useState(0);
  
  const onRefreshRef = useRef(onRefresh);
  onRefreshRef.current = onRefresh;
  
  // Use a ref as a lock to prevent concurrent refresh operations
  const isRefreshingRef = useRef(false);

  const refresh = useCallback(async () => {
    // Use ref for immediate lock check, then update state
    if (isRefreshingRef.current) return;
    
    isRefreshingRef.current = true;
    setIsRefreshing(true);
    
    try {
      await onRefreshRef.current();
      setLastRefreshTime(new Date());
      setRefreshCount(c => c + 1);
    } catch (error) {
      console.error('Auto refresh error:', error);
    } finally {
      isRefreshingRef.current = false;
      setIsRefreshing(false);
    }
  }, []); // Remove isRefreshing from deps - using ref instead

  // Initial refresh
  useEffect(() => {
    refresh();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Auto refresh timer
  useEffect(() => {
    if (!enabled || interval <= 0) return;

    const timerId = window.setInterval(() => {
      refresh();
    }, interval);

    return () => {
      window.clearInterval(timerId);
    };
  }, [enabled, interval, refresh]);

  const setIntervalMs = useCallback((ms: number) => {
    setIntervalState(ms);
  }, []);

  return {
    interval,
    setInterval: setIntervalMs,
    enabled,
    setEnabled,
    refresh,
    lastRefreshTime,
    isRefreshing,
    refreshCount,
  };
}

/**
 * Format last refresh time
 */
export function formatLastRefreshTime(time: Date | null): string {
  if (!time) return 'Never';
  
  const now = new Date();
  const diff = now.getTime() - time.getTime();
  
  if (diff < 1000) return 'Just now';
  if (diff < 60000) return `${Math.floor(diff / 1000)}s ago`;
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  
  return time.toLocaleTimeString();
}
