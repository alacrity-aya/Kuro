import { useEffect, useRef, useCallback } from 'react';
import * as echarts from 'echarts';
import type { EChartsOption } from 'echarts';
import './PacketLossGauge.css';

interface PacketLossGaugeProps {
  value: number; // percentage (0-100)
  title?: string;
  height?: number;
}

/** Maximum reasonable packet loss percentage for display */
const MAX_DISPLAY_LOSS = 100;

/** Clamp value to reasonable range */
function clampValue(val: number): number {
  if (!Number.isFinite(val)) return 0;
  return Math.max(0, Math.min(val, MAX_DISPLAY_LOSS));
}

export function PacketLossGauge({ 
  value, 
  title = 'Packet Loss',
  height = 180 
}: PacketLossGaugeProps) {
  const chartRef = useRef<HTMLDivElement>(null);
  const chartInstance = useRef<echarts.ECharts | null>(null);

  // Clamp value to reasonable range
  const clampedValue = clampValue(value);

  const handleResize = useCallback(() => {
    chartInstance.current?.resize();
  }, []);

  // Separate resize event listener to avoid re-adding on every render
  useEffect(() => {
    window.addEventListener('resize', handleResize);
    return () => {
      window.removeEventListener('resize', handleResize);
    };
  }, [handleResize]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (chartInstance.current) {
        chartInstance.current.dispose();
        chartInstance.current = null;
      }
    };
  }, []);

  // Chart render/update effect
  useEffect(() => {
    if (!chartRef.current) return;

    if (!chartInstance.current) {
      chartInstance.current = echarts.init(chartRef.current);
    }

    // Determine color based on packet loss severity
    const getColor = (val: number): string => {
      if (val < 1) return '#27AE60'; // Green - good
      if (val < 5) return '#F39C12'; // Orange - warning
      return '#E74C3C'; // Red - critical
    };

    // For values > 10%, adjust max scale dynamically
    const maxScale = Math.max(10, Math.ceil(clampedValue / 10) * 10);

    const option: EChartsOption = {
      series: [
        {
          type: 'gauge',
          center: ['50%', '55%'],
          radius: '75%',
          startAngle: 200,
          endAngle: -20,
          min: 0,
          max: maxScale,
          splitNumber: 10,
          itemStyle: {
            color: getColor(clampedValue),
          },
          progress: {
            show: true,
            width: 18,
          },
          pointer: {
            show: false,
          },
          axisLine: {
            lineStyle: {
              width: 18,
              color: [[1, '#EAEDED']],
            },
          },
          axisTick: {
            show: false,
          },
          splitLine: {
            show: false,
          },
          axisLabel: {
            show: false,
          },
          anchor: {
            show: false,
          },
          title: {
            show: false,
          },
          detail: {
            valueAnimation: true,
            width: '60%',
            lineHeight: 24,
            borderRadius: 8,
            offsetCenter: [0, '10%'],
            fontSize: 20,
            fontWeight: 'bold',
            formatter: (val: number) => `${val.toFixed(2)}%`,
            color: getColor(clampedValue),
          },
          data: [
            {
              value: clampedValue,
            },
          ],
        },
      ],
    };

    chartInstance.current.setOption(option);
  }, [clampedValue]);

  return (
    <div className="packet-loss-gauge-wrapper">
      <div className="packet-loss-gauge__title">{title}</div>
      <div
        ref={chartRef}
        className="packet-loss-gauge"
        style={{ height: `${height}px` }}
      />
    </div>
  );
}
