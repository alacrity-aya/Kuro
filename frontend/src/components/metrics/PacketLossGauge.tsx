import { useEffect, useRef } from 'react';
import * as echarts from 'echarts';
import type { EChartsOption } from 'echarts';
import './PacketLossGauge.css';

interface PacketLossGaugeProps {
  value: number; // percentage (0-100)
  title?: string;
  height?: number;
}

export function PacketLossGauge({ 
  value, 
  title = 'Packet Loss',
  height = 180 
}: PacketLossGaugeProps) {
  const chartRef = useRef<HTMLDivElement>(null);
  const chartInstance = useRef<echarts.ECharts | null>(null);

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

    const option: EChartsOption = {
      title: {
        text: title,
        left: 'center',
        top: 10,
        textStyle: {
          fontSize: 14,
          fontWeight: 500,
          color: '#333',
        },
      },
      series: [
        {
          type: 'gauge',
          center: ['50%', '60%'],
          radius: '80%',
          startAngle: 200,
          endAngle: -20,
          min: 0,
          max: 10,
          splitNumber: 10,
          itemStyle: {
            color: getColor(value),
          },
          progress: {
            show: true,
            width: 20,
          },
          pointer: {
            show: false,
          },
          axisLine: {
            lineStyle: {
              width: 20,
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
            lineHeight: 30,
            borderRadius: 8,
            offsetCenter: [0, '15%'],
            fontSize: 24,
            fontWeight: 'bold',
            formatter: (val: number) => `${val.toFixed(2)}%`,
            color: getColor(value),
          },
          data: [
            {
              value: value,
            },
          ],
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
  }, [value, title]);

  return (
    <div 
      ref={chartRef} 
      className="packet-loss-gauge" 
      style={{ height: `${height}px` }}
    />
  );
}
