/**
 * Pod Selector Component
 * 
 * 允许用户选择要监控的 Pod，支持多选。
 * 从 Prometheus 获取 pod 标签值列表。
 * 
 * TODO: 需要后端 API - Prometheus API: /api/v1/label/pod/values
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import './PodSelector.css';

export interface PodSelectorProps {
  /** Selected pod names */
  value: string[];
  /** Callback when selection changes */
  onChange: (pods: string[]) => void;
  /** Available pods (if not provided, will fetch from Prometheus) */
  pods?: string[];
  /** Placeholder text */
  placeholder?: string;
  /** Disabled state */
  disabled?: boolean;
  /** Show "All" option */
  showAllOption?: boolean;
  /** "All" option label */
  allOptionLabel?: string;
  /** Max visible items before scroll */
  maxVisibleItems?: number;
  /** Loading state */
  isLoading?: boolean;
}

/**
 * PodSelector Component
 * 
 * A multi-select dropdown for selecting pods to monitor.
 * 
 * Features:
 * - Multi-select with checkboxes
 * - Search/filter functionality
 * - "Select All" option
 * - Keyboard navigation
 * - Loading state
 */
export function PodSelector({
  value,
  onChange,
  pods: providedPods,
  placeholder = 'Select pods...',
  disabled = false,
  showAllOption = true,
  allOptionLabel = 'All Pods',
  maxVisibleItems = 8,
  isLoading = false,
}: PodSelectorProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [pods, setPods] = useState<string[]>(providedPods || []);
  const containerRef = useRef<HTMLDivElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);

  // Update pods when provided externally
  useEffect(() => {
    if (providedPods && providedPods.length > 0) {
      setPods(providedPods);
    }
  }, [providedPods]);

  // Focus search input when dropdown opens
  useEffect(() => {
    if (isOpen && searchInputRef.current) {
      searchInputRef.current.focus();
    }
  }, [isOpen]);

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Filter pods by search term
  const filteredPods = pods.filter(pod =>
    pod.toLowerCase().includes(searchTerm.toLowerCase())
  );

  // Check if all pods are selected
  const isAllSelected = value.length === pods.length && pods.length > 0;

  // Toggle dropdown
  const toggleDropdown = useCallback(() => {
    if (!disabled) {
      setIsOpen(prev => !prev);
    }
  }, [disabled]);

  // Handle pod selection toggle
  const togglePod = useCallback((pod: string) => {
    if (value.includes(pod)) {
      onChange(value.filter(p => p !== pod));
    } else {
      onChange([...value, pod]);
    }
  }, [value, onChange]);

  // Handle "Select All" toggle
  const toggleAll = useCallback(() => {
    if (isAllSelected) {
      onChange([]);
    } else {
      onChange([...pods]);
    }
  }, [isAllSelected, pods, onChange]);

  // Handle keyboard navigation
  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      setIsOpen(false);
    } else if (e.key === 'Enter' && !isOpen) {
      setIsOpen(true);
    }
  }, [isOpen]);

  // Display text for the selected value
  const displayText = value.length === 0
    ? placeholder
    : value.length === pods.length
      ? allOptionLabel
      : value.length === 1
        ? value[0]
        : `${value.length} pods selected`;

  return (
    <div
      ref={containerRef}
      className={`pod-selector ${disabled ? 'pod-selector--disabled' : ''} ${isOpen ? 'pod-selector--open' : ''}`}
      onKeyDown={handleKeyDown}
    >
      {/* Trigger button */}
      <button
        type="button"
        className="pod-selector__trigger"
        onClick={toggleDropdown}
        disabled={disabled}
        aria-haspopup="listbox"
        aria-expanded={isOpen}
      >
        <span className="pod-selector__value">{displayText}</span>
        <span className="pod-selector__arrow">
          {isLoading ? '⏳' : isOpen ? '▲' : '▼'}
        </span>
      </button>

      {/* Dropdown panel */}
      {isOpen && (
        <div className="pod-selector__dropdown" role="listbox">
          {/* Search input */}
          <div className="pod-selector__search">
            <input
              ref={searchInputRef}
              type="text"
              className="pod-selector__search-input"
              placeholder="Search pods..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>

          {/* Options list */}
          <ul
            className="pod-selector__options"
            style={{ maxHeight: `${maxVisibleItems * 32 + 8}px` }}
          >
            {/* "All" option */}
            {showAllOption && (
              <li className="pod-selector__option">
                <label className="pod-selector__option-label">
                  <input
                    type="checkbox"
                    checked={isAllSelected}
                    onChange={toggleAll}
                    className="pod-selector__checkbox"
                  />
                  <span className="pod-selector__option-text pod-selector__option-text--all">
                    {allOptionLabel}
                  </span>
                </label>
              </li>
            )}

            {/* Divider */}
            {showAllOption && filteredPods.length > 0 && (
              <li className="pod-selector__divider" />
            )}

            {/* Pod options */}
            {filteredPods.map(pod => (
              <li key={pod} className="pod-selector__option">
                <label className="pod-selector__option-label">
                  <input
                    type="checkbox"
                    checked={value.includes(pod)}
                    onChange={() => togglePod(pod)}
                    className="pod-selector__checkbox"
                  />
                  <span className="pod-selector__option-text">{pod}</span>
                </label>
              </li>
            ))}

            {/* Empty state */}
            {filteredPods.length === 0 && !isLoading && (
              <li className="pod-selector__empty">
                {searchTerm ? 'No matching pods' : 'No pods available'}
              </li>
            )}

            {/* Loading state */}
            {isLoading && (
              <li className="pod-selector__loading">
                Loading pods...
              </li>
            )}
          </ul>

          {/* Selection summary */}
          <div className="pod-selector__summary">
            {value.length} of {pods.length} selected
          </div>
        </div>
      )}
    </div>
  );
}

export default PodSelector;
