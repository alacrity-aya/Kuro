// src/components/MonitorPanel.tsx
import React from 'react';
import { useStore } from '../store';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';
import { Activity, X } from 'lucide-react';

export const MonitorPanel = () => {
    const { isMonitoring, selectedLinkIds, trafficHistory, links, toggleLinkSelection } = useStore();


    if (!isMonitoring || selectedLinkIds.length === 0) return null;

    return (
        <div className="absolute bottom-4 left-4 right-[25rem] z-20 flex gap-4 overflow-x-auto pb-2 pointer-events-none">
            {selectedLinkIds.map(linkId => {
                const link = links.find(l => l.id === linkId);
                const data = trafficHistory[linkId] || [];

                const latest = data.length > 0 ? data[data.length - 1] : null;

                if (!link) return null;

                return (
                    <div
                        key={linkId}
                        className="pointer-events-auto bg-[#25262b]/90 backdrop-blur border border-[#373a40] rounded-lg shadow-xl w-80 h-48 flex flex-col overflow-hidden animate-in slide-in-from-bottom-10 fade-in duration-300"
                    >
                        {/* Header */}
                        <div className="flex justify-between items-center px-3 py-2 border-b border-[#373a40] bg-black/20">
                            <div className="flex flex-col min-w-0">
                                <span className="text-xs font-bold text-gray-200 truncate flex items-center gap-1">
                                    <Activity size={12} className="text-green-400" />
                                    {link.source} → {link.target}
                                </span>
                                <span className="text-[10px] text-gray-500 truncate">
                                    RX: {latest ? (latest.rx_bps / 1000000).toFixed(2) : 0} Mbps
                                </span>
                            </div>
                            <button
                                onClick={() => toggleLinkSelection(linkId)}
                                className="text-gray-500 hover:text-white transition-colors"
                            >
                                <X size={14} />
                            </button>
                        </div>

                        {/* Chart */}
                        <div className="flex-1 w-full min-h-0 relative">
                            {/* 使用 ResponsiveContainer 让图表自适应容器 */}
                            <ResponsiveContainer width="100%" height="100%">
                                <AreaChart data={data} margin={{ top: 5, right: 0, left: -20, bottom: 0 }}>
                                    <defs>
                                        <linearGradient id={`grad-${linkId}`} x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor="#4dabf7" stopOpacity={0.3} />
                                            <stop offset="95%" stopColor="#4dabf7" stopOpacity={0} />
                                        </linearGradient>
                                    </defs>
                                    <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#444" opacity={0.5} />
                                    <XAxis dataKey="timestamp" hide />
                                    <YAxis
                                        tick={{ fontSize: 10, fill: '#888' }}
                                        tickFormatter={(val) => `${(val / 1000000).toFixed(0)}M`}
                                        domain={[0, 'auto']}
                                    />
                                    <Tooltip
                                        contentStyle={{ backgroundColor: '#1a1b1e', border: '1px solid #373a40', borderRadius: '4px', fontSize: '12px' }}
                                        itemStyle={{ color: '#4dabf7' }}
                                        labelStyle={{ display: 'none' }}

                                        formatter={(value: any) => [`${(Number(value || 0) / 1000000).toFixed(2)} Mbps`, 'Rate']}
                                    />
                                    <Area
                                        type="monotone"
                                        dataKey="rx_bps"
                                        stroke="#4dabf7"
                                        strokeWidth={2}
                                        fill={`url(#grad-${linkId})`}
                                        isAnimationActive={false}
                                    />
                                </AreaChart>
                            </ResponsiveContainer>
                        </div>
                    </div>
                );
            })}
        </div>
    );
};
