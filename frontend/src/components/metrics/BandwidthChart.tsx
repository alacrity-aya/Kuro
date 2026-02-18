import { useEffect, useRef } from 'react';
import * as echarts from 'echarts';
import type { EChartsOption } from 'echarts';
import type { TimeSeriesPoint } from '../../types/api';
import './BandwidthChart.css';

interface BandwidthChartProps {
  data: TimeSeriesPoint[];
  title?: string;
  maxBandwidth?: number; // in Mbps
  height?: number;
}

export function BandwidthChart({ 
  data, 
  title = 'Bandwidth Usage', 
  maxBandwidth = 100,
  height = 200 
}: BandwidthChartProps) {
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
          return `${date.toLocaleTimeString()}<br/>Bandwidth: ${point.value.toFixed(1)} Mbps`;
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
        name: 'Mbps',
        nameTextStyle: {
          fontSize: 10,
          color: '#666',
        },
        min: 0,
        max: maxBandwidth,
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
          name: 'Bandwidth',
          type: 'line',
          data: values,
          smooth: true,
          symbol: 'none',
          lineStyle: {
            width: 2,
            color: '#4A90D9',
          },
          areaStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: 'rgba(74, 144, 217, 0.4)' },
              { offset: 1, color: 'rgba(74, 144, 217, 0.05)' },
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
  }, [data, title, maxBandwidth]);

  return (
    <div 
      ref={chartRef} 
      className="bandwidth-chart" 
      style={{ height: `${height}px` }}
    />
  );
}
