/**
 * Auto Refresh Hook
 * 用于控制仪表板自动刷新间隔
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
  /** 初始刷新间隔 (ms)，默认 5000 */
  initialInterval?: number;
  /** 是否初始启用自动刷新，默认 true */
  initialEnabled?: boolean;
  /** 刷新回调函数 */
  onRefresh: () => void | Promise<void>;
}

export interface UseAutoRefreshReturn {
  /** 当前刷新间隔 */
  interval: number;
  /** 设置刷新间隔 */
  setInterval: (ms: number) => void;
  /** 是否启用自动刷新 */
  enabled: boolean;
  /** 设置是否启用 */
  setEnabled: (enabled: boolean) => void;
  /** 手动触发刷新 */
  refresh: () => void;
  /** 上次刷新时间 */
  lastRefreshTime: Date | null;
  /** 是否正在刷新 */
  isRefreshing: boolean;
  /** 刷新计数 */
  refreshCount: number;
}

/**
 * 自动刷新 Hook
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

  // 初始刷新
  useEffect(() => {
    refresh();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // 自动刷新定时器
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
 * 格式化上次刷新时间
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
