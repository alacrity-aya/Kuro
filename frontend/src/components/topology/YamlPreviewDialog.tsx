import { useState, useCallback, useEffect, memo } from 'react';
import { downloadYaml, copyYamlToClipboard } from '../../utils/topologyConverter';
import './YamlPreviewDialog.css';

// ============================================================================
// Types
// ============================================================================

export interface YamlPreviewDialogProps {
  isOpen: boolean;
  yaml: string;
  topologyName: string;
  errors: string[];
  warnings: string[];
  onClose: () => void;
  onSave?: () => void;
}

// ============================================================================
// Component
// ============================================================================

function YamlPreviewDialog({
  isOpen,
  yaml,
  topologyName,
  errors,
  warnings,
  onClose,
  onSave,
}: YamlPreviewDialogProps) {
  const [copied, setCopied] = useState(false);
  const [downloaded, setDownloaded] = useState(false);

  // Reset state when dialog opens
  useEffect(() => {
    if (isOpen) {
      setCopied(false);
      setDownloaded(false);
    }
  }, [isOpen]);

  // Handle copy to clipboard
  const handleCopy = useCallback(async () => {
    const success = await copyYamlToClipboard(yaml);
    if (success) {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }, [yaml]);

  // Handle download
  const handleDownload = useCallback(() => {
    downloadYaml(yaml, `${topologyName || 'topology'}.yaml`);
    setDownloaded(true);
    setTimeout(() => setDownloaded(false), 2000);
  }, [yaml, topologyName]);

  // Handle save
  const handleSave = useCallback(() => {
    onSave?.();
    onClose();
  }, [onSave, onClose]);

  // Handle keyboard events
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (!isOpen) return;
      
      if (e.key === 'Escape') {
        onClose();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const hasErrors = errors.length > 0;
  const hasWarnings = warnings.length > 0;

  return (
    <div className="ypd-overlay" onClick={onClose}>
      <div className="ypd-dialog" onClick={(e) => e.stopPropagation()}>
        <div className="ypd-header">
          <h2 className="ypd-title">Topology YAML Preview</h2>
          <button className="ypd-close" onClick={onClose} title="Close (Esc)">
            ×
          </button>
        </div>

        <div className="ypd-content">
          {/* Errors */}
          {hasErrors && (
            <div className="ypd-errors">
              <h3 className="ypd-errors__title">❌ Errors</h3>
              <ul className="ypd-errors__list">
                {errors.map((error, index) => (
                  <li key={index} className="ypd-errors__item">
                    {error}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Warnings */}
          {hasWarnings && (
            <div className="ypd-warnings">
              <h3 className="ypd-warnings__title">⚠️ Warnings</h3>
              <ul className="ypd-warnings__list">
                {warnings.map((warning, index) => (
                  <li key={index} className="ypd-warnings__item">
                    {warning}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* YAML Preview */}
          {!hasErrors && (
            <div className="ypd-yaml">
              <div className="ypd-yaml__header">
                <span className="ypd-yaml__label">YAML Output</span>
                <div className="ypd-yaml__actions">
                  <button
                    className="ypd-btn ypd-btn--small"
                    onClick={handleCopy}
                    title="Copy to clipboard"
                  >
                    {copied ? '✓ Copied!' : '📋 Copy'}
                  </button>
                  <button
                    className="ypd-btn ypd-btn--small"
                    onClick={handleDownload}
                    title="Download as file"
                  >
                    {downloaded ? '✓ Downloaded!' : '📥 Download'}
                  </button>
                </div>
              </div>
              <pre className="ypd-yaml__content">
                <code>{yaml}</code>
              </pre>
            </div>
          )}
        </div>

        <div className="ypd-footer">
          <button className="ypd-btn ypd-btn--secondary" onClick={onClose}>
            Cancel
          </button>
          {!hasErrors && (
            <button className="ypd-btn ypd-btn--primary" onClick={handleSave}>
              Save Topology
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

export default memo(YamlPreviewDialog);
