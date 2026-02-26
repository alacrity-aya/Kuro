// frontend/src/components/topology/TrafficControlFilter.tsx

import { useMemo } from 'react';
import type { TrafficControl } from '../../types/api';
import { getTrafficControlColor } from '../../utils/colorPalette';
import './TrafficControlFilter.css';

interface TrafficControlFilterProps {
  trafficControls: TrafficControl[];
  selectedIds: string[];
  onToggle: (id: string) => void;
  onClear: () => void;
}

export function TrafficControlFilter({
  trafficControls,
  selectedIds,
  onToggle,
  onClear,
}: TrafficControlFilterProps) {
  // Build TC list with colors
  const tcWithColors = useMemo(() => 
    trafficControls.map((tc, index) => ({
      id: tc.metadata.uid,
      name: tc.metadata.name,
      color: getTrafficControlColor(index),
      policy: tc.spec.policy,
      phase: tc.status?.phase ?? 'Unknown',
    })),
    [trafficControls]
  );

  if (trafficControls.length === 0) {
    return (
      <div className="tc-filter tc-filter--empty">
        <span>No traffic controls</span>
      </div>
    );
  }

  return (
    <div className="tc-filter">
      <div className="tc-filter__header">
        <span className="tc-filter__count">{selectedIds.length} selected</span>
        {selectedIds.length > 0 && (
          <button className="tc-filter__clear" onClick={onClear}>
            Clear
          </button>
        )}
      </div>
      <div className="tc-filter__list">
        {tcWithColors.map((tc) => {
          const isSelected = selectedIds.includes(tc.id);
          return (
            <button
              key={tc.id}
              className={`tc-filter__item ${isSelected ? 'tc-filter__item--selected' : ''}`}
              onClick={() => onToggle(tc.id)}
            >
              <span 
                className="tc-filter__color" 
                style={{ backgroundColor: tc.color }}
              />
              <span className="tc-filter__name">{tc.name}</span>
              <span className="tc-filter__policy">
                {tc.policy.bandwidth}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
