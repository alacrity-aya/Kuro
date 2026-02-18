import { useEffect, useRef } from 'react';
import * as echarts from 'echarts';
import type { EChartsOption } from 'echarts';
import type { TimeSeriesPoint } from '../../types/api';
import './LatencyChart.css';

interface LatencyChartProps {
  data: TimeSeriesPoint[];
  title?: string;
  maxLatency?: number; // in ms
  height?: number;
}

export function LatencyChart({ 
  data, 
  title = 'Latency', 
  maxLatency = 100,
  height = 200 
}: LatencyChartProps) {
  const chartRef = useRef<HTMLDivElement>(null);
  const chartInstance = useRef<echarts.ECharts | null>(null);

  useEffect(() => {
    if (!chartRef.current) return;

    if (!chartInstance.current) {
      chartInstance.current = echarts.init(chartRef.current);
    }

    const timestamps = data.map(d => d.timestamp);
    const values = data.map(d => d.value);

    const option: EChartsOption = {
      title: {
        text: title,
        left: 'center',
        textStyle: {
          fontSize: 14,
          fontWeight: 500,
          color: '#333',
        },
      },
      tooltip: {
        trigger: 'axis',
        formatter: (params: unknown) => {
          const p = params as Array<{ axisValue: number; value: number }>;
          const point = p[0];
          const date = new Date(point.axisValue);
          return `${date.toLocaleTimeString()}<br/>Latency: ${point.value.toFixed(1)} ms`;
        },
      },
      grid: {
        left: '10%',
        right: '5%',
        top: '20%',
        bottom: '15%',
      },
      xAxis: {
        type: 'category',
        data: timestamps,
        axisLabel: {
          formatter: (value: string | number) => {
            const date = new Date(Number(value));
            return date.toLocaleTimeString('en-US', { 
              hour: '2-digit', 
              minute: '2-digit' 
            });
          },
          fontSize: 10,
          color: '#666',
        },
        axisLine: {
          lineStyle: { color: '#ddd' },
        },
      },
      yAxis: {
        type: 'value',
        name: 'ms',
        nameTextStyle: {
          fontSize: 10,
          color: '#666',
        },
        min: 0,
        max: maxLatency,
        axisLabel: {
          fontSize: 10,
          color: '#666',
        },
        splitLine: {
          lineStyle: { color: '#eee', type: 'dashed' },
        },
      },
      series: [
        {
          name: 'Latency',
          type: 'line',
          data: values,
          smooth: true,
          symbol: 'none',
          lineStyle: {
            width: 2,
            color: '#E67E22',
          },
          areaStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: 'rgba(230, 126, 34, 0.4)' },
              { offset: 1, color: 'rgba(230, 126, 34, 0.05)' },
            ]),
          },
        },
      ],
    };

    chartInstance.current.setOption(option);

    const handleResize = () => {
      chartInstance.current?.resize();
    };

    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
    };
  }, [data, title, maxLatency]);

  return (
    <div 
      ref={chartRef} 
      className="latency-chart" 
      style={{ height: `${height}px` }}
    />
  );
}
