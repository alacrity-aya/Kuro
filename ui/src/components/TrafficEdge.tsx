// src/components/TrafficEdge.tsx
import React from 'react';
import { BaseEdge, EdgeLabelRenderer, type EdgeProps, getBezierPath } from '@xyflow/react';
import { useStore } from '../store';
import clsx from 'clsx';


const formatBps = (bps: number) => {
    if (bps === 0) return '0 bps';
    if (bps >= 1000000000) return `${(bps / 1000000000).toFixed(2)} Gbps`;
    if (bps >= 1000000) return `${(bps / 1000000).toFixed(2)} Mbps`;
    if (bps >= 1000) return `${(bps / 1000).toFixed(0)} Kbps`;
    return `${bps.toFixed(0)} bps`;
};

export const TrafficEdge: React.FC<EdgeProps> = ({
    id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, style, markerEnd, label
}) => {

    const [edgePath, labelX, labelY] = getBezierPath({
        sourceX, sourceY, sourcePosition,
        targetX, targetY, targetPosition,
    });


    const { isMonitoring, trafficData, selectedLinkIds, toggleLinkSelection } = useStore();


    const isSelected = selectedLinkIds.includes(id);
    const stats = trafficData[id];


    const handleEdgeClick = (e: React.MouseEvent) => {
        e.stopPropagation();
        toggleLinkSelection(id);
    };


    const hasTraffic = isMonitoring && stats && stats.rx_bps > 100;
    const hasDrops = isMonitoring && stats && stats.drops > 0;


    let strokeColor = '#4dabf7';
    let strokeWidth = 2;


    if (isSelected) {
        strokeWidth = 4;
        strokeColor = '#339af0';
    }


    if (isMonitoring) {
        if (hasDrops) {
            strokeColor = '#fa5252';
        } else if (hasTraffic) {
            strokeColor = '#51cf66';
        } else if (isSelected) {

        }
    }

    return (
        <>
            {/* 可见的连线 */}
            <BaseEdge
                path={edgePath}
                markerEnd={markerEnd}
                style={{ ...style, stroke: strokeColor, strokeWidth, transition: 'all 0.3s', cursor: 'pointer' }}
            />

            <BaseEdge
                path={edgePath}
                style={{ strokeWidth: 20, stroke: 'transparent', cursor: 'pointer' }}
            />

            <EdgeLabelRenderer>
                <div
                    style={{
                        position: 'absolute',
                        transform: `translate(-50%, -50%) translate(${labelX}px,${labelY}px)`,
                        pointerEvents: 'all',
                        zIndex: 10,
                    }}
                    className={clsx(
                        "px-2 py-1 rounded text-[10px] font-bold shadow-lg transition-all border cursor-pointer select-none",

                        isSelected
                            ? (isMonitoring ? "bg-gray-900 text-green-400 border-green-500 scale-110" : "bg-blue-900/80 text-white border-blue-400 scale-110")
                            : "bg-[#1a1b1e] text-gray-400 border-gray-600 hover:border-gray-400"
                    )}

                    onClick={handleEdgeClick}
                >
                    {isMonitoring && isSelected && stats ? (
                        <div className="flex flex-col items-center min-w-[80px]">
                            <span className="text-xs">{formatBps(stats.rx_bps)}</span>
                            <div className="flex gap-2 text-[8px] text-gray-400 mt-0.5">
                                <span>TX: {formatBps(stats.tx_bps)}</span>
                                {hasDrops && <span className="text-red-500 font-bold">Drop: {stats.drops}</span>}
                            </div>
                        </div>
                    ) : (

                        <span>{label}</span>
                    )}
                </div>
            </EdgeLabelRenderer>
        </>
    );
};
