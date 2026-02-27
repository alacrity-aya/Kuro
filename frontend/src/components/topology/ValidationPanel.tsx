import { memo, useMemo, useCallback } from 'react';
import type { ValidationResult, ValidationIssue } from '../../utils/topologyValidator';
import './ValidationPanel.css';

// ============================================================================
// Types
// ============================================================================

export interface ValidationPanelProps {
  validationResult: ValidationResult;
  collapsed?: boolean;
  onToggle?: () => void;
  onIssueClick?: (issue: ValidationIssue) => void;
  showSummary?: boolean;
}

// ============================================================================
// Helper Functions
// ============================================================================

function getIssueIcon(type: ValidationIssue['type']): string {
  switch (type) {
    case 'error':
      return '❌';
    case 'warning':
      return '⚠️';
    case 'info':
    default:
      return 'ℹ️';
  }
}

// ============================================================================
// Component
// ============================================================================

function ValidationPanel({
  validationResult,
  collapsed = false,
  onToggle,
  onIssueClick,
  showSummary = true,
}: ValidationPanelProps) {
  const { hasErrors, hasWarnings, issues, summary } = validationResult;

  // Separate issues by type
  const { errors, warnings, infos } = useMemo(() => {
    const errors: ValidationIssue[] = [];
    const warnings: ValidationIssue[] = [];
    const infos: ValidationIssue[] = [];

    issues.forEach((issue) => {
      switch (issue.type) {
        case 'error':
          errors.push(issue);
          break;
        case 'warning':
          warnings.push(issue);
          break;
        case 'info':
          infos.push(issue);
          break;
      }
    });

    return { errors, warnings, infos };
  }, [issues]);

  // Get title status
  const titleStatus = useMemo(() => {
    if (hasErrors) return 'has-errors';
    if (hasWarnings) return 'has-warnings';
    return 'valid';
  }, [hasErrors, hasWarnings]);

  // Get title icon
  const titleIcon = useMemo(() => {
    if (hasErrors) return '❌';
    if (hasWarnings) return '⚠️';
    return '✅';
  }, [hasErrors, hasWarnings]);

  // Handle issue click
  const handleIssueClick = useCallback(
    (issue: ValidationIssue) => {
      onIssueClick?.(issue);
    },
    [onIssueClick]
  );

  // Render an issue item
  const renderIssue = (issue: ValidationIssue) => (
    <div
      key={issue.id}
      className={`issue-item ${issue.type}`}
      onClick={() => handleIssueClick(issue)}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          handleIssueClick(issue);
        }
      }}
    >
      <span className="issue-icon">{getIssueIcon(issue.type)}</span>
      <div className="issue-content">
        <div className="issue-message">{issue.message}</div>
        {issue.suggestion && (
          <div className="issue-suggestion">💡 {issue.suggestion}</div>
        )}
        {issue.nodeId && (
          <div className="issue-location">Node: {issue.nodeId}</div>
        )}
        {issue.edgeId && (
          <div className="issue-location">Link: {issue.edgeId}</div>
        )}
      </div>
    </div>
  );

  if (!hasErrors && !hasWarnings && issues.length === 0) {
    return (
      <div className="validation-panel">
        <div className="validation-header">
          <span className="validation-title valid">
            <span className="icon">✅</span>
            Validation
          </span>
        </div>
        <div className="no-issues">
          <span className="icon">🎉</span>
          <span>No issues found</span>
        </div>
      </div>
    );
  }

  return (
    <div className={`validation-panel ${collapsed ? 'collapsed' : ''}`}>
      <div className="validation-header">
        <span className={`validation-title ${titleStatus}`}>
          <span className="icon">{titleIcon}</span>
          Validation
          {hasErrors && (
            <span className="validation-count errors">{errors.length}</span>
          )}
          {hasWarnings && (
            <span className="validation-count warnings">{warnings.length}</span>
          )}
        </span>
        {onToggle && (
          <button
            className={`validation-toggle ${collapsed ? '' : 'expanded'}`}
            onClick={onToggle}
            aria-label={collapsed ? 'Expand validation panel' : 'Collapse validation panel'}
          >
            ▼
          </button>
        )}
      </div>

      {!collapsed && showSummary && (
        <div className="validation-summary">
          <span className="summary-item">
            <span className="label">Nodes:</span>
            <span className="value">{summary.totalNodes}</span>
          </span>
          <span className="summary-item">
            <span className="label">Links:</span>
            <span className="value">{summary.totalEdges}</span>
          </span>
          {summary.isolatedNodes > 0 && (
            <span className="summary-item">
              <span className="label">Isolated:</span>
              <span className="value" style={{ color: '#f59e0b' }}>
                {summary.isolatedNodes}
              </span>
            </span>
          )}
        </div>
      )}

      {!collapsed && (
        <div className="validation-issues">
          {/* Render errors first */}
          {errors.map(renderIssue)}
          {/* Then warnings */}
          {warnings.map(renderIssue)}
          {/* Finally info */}
          {infos.map(renderIssue)}
        </div>
      )}
    </div>
  );
}

// ============================================================================
// Quick Stats Component (for toolbar)
// ============================================================================

export interface ValidationQuickStatsProps {
  validationResult: ValidationResult;
  onClick?: () => void;
}

export function ValidationQuickStats({ validationResult, onClick }: ValidationQuickStatsProps) {
  const { hasErrors, hasWarnings, issues } = validationResult;
  
  // Count errors and warnings from issues array
  const errorCount = issues.filter((i) => i.type === 'error').length;
  const warningCount = issues.filter((i) => i.type === 'warning').length;

  if (!hasErrors && !hasWarnings) {
    return (
      <div className="validation-quick-stats valid">
        <span className="quick-stat">
          <span className="icon">✅</span>
          Valid
        </span>
      </div>
    );
  }

  const statusClass = hasErrors ? 'errors' : 'warnings';
  const icon = hasErrors ? '❌' : '⚠️';
  const count = hasErrors ? errorCount : warningCount;

  return (
    <div
      className={`validation-quick-stats has-issues ${statusClass}`}
      onClick={onClick}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          onClick?.();
        }
      }}
    >
      <span className="quick-stat">
        <span className="icon">{icon}</span>
        {count} {hasErrors ? 'error' : 'warning'}{count > 1 ? 's' : ''}
      </span>
    </div>
  );
}

export default memo(ValidationPanel);
