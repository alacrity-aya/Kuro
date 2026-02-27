import { memo, useCallback, useEffect } from 'react';
import './UndoRedoButtons.css';

export interface UndoRedoButtonsProps {
  /** Whether undo is available */
  canUndo: boolean;
  /** Whether redo is available */
  canRedo: boolean;
  /** Callback when undo is clicked */
  onUndo: () => void;
  /** Callback when redo is clicked */
  onRedo: () => void;
  /** Whether to enable keyboard shortcuts (default: true) */
  enableShortcuts?: boolean;
  /** Optional additional class name */
  className?: string;
}

/**
 * Undo/Redo buttons component with keyboard shortcuts support.
 * Supports Ctrl+Z (Cmd+Z on Mac) for undo and Ctrl+Shift+Z (Cmd+Shift+Z) or Ctrl+Y for redo.
 */
function UndoRedoButtons({
  canUndo,
  canRedo,
  onUndo,
  onRedo,
  enableShortcuts = true,
  className = '',
}: UndoRedoButtonsProps) {
  // Handle keyboard shortcuts
  useEffect(() => {
    if (!enableShortcuts) return;

    const handleKeyDown = (event: KeyboardEvent) => {
      // Check for Ctrl/Cmd key
      const isMeta = event.metaKey || event.ctrlKey;
      
      if (isMeta && !event.shiftKey && event.key === 'z') {
        // Ctrl+Z or Cmd+Z: Undo
        event.preventDefault();
        if (canUndo) {
          onUndo();
        }
      } else if (isMeta && event.shiftKey && event.key === 'z') {
        // Ctrl+Shift+Z or Cmd+Shift+Z: Redo
        event.preventDefault();
        if (canRedo) {
          onRedo();
        }
      } else if (isMeta && event.key === 'y') {
        // Ctrl+Y or Cmd+Y: Redo (Windows convention)
        event.preventDefault();
        if (canRedo) {
          onRedo();
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [canUndo, canRedo, onUndo, onRedo, enableShortcuts]);

  const handleUndoClick = useCallback(() => {
    if (canUndo) {
      onUndo();
    }
  }, [canUndo, onUndo]);

  const handleRedoClick = useCallback(() => {
    if (canRedo) {
      onRedo();
    }
  }, [canRedo, onRedo]);

  return (
    <div className={`undo-redo-buttons ${className}`}>
      <button
        className="undo-redo-btn"
        onClick={handleUndoClick}
        disabled={!canUndo}
        title={canUndo ? 'Undo (Ctrl+Z)' : 'No history to undo'}
        aria-label="Undo"
      >
        <svg
          width="16"
          height="16"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path d="M3 7v6h6" />
          <path d="M21 17a9 9 0 0 0-9-9 9 9 0 0 0-6 2.3L3 13" />
        </svg>
      </button>
      <button
        className="undo-redo-btn"
        onClick={handleRedoClick}
        disabled={!canRedo}
        title={canRedo ? 'Redo (Ctrl+Shift+Z)' : 'No history to redo'}
        aria-label="Redo"
      >
        <svg
          width="16"
          height="16"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path d="M21 7v6h-6" />
          <path d="M3 17a9 9 0 0 1 9-9 9 9 0 0 1 6 2.3l3 2.7" />
        </svg>
      </button>
    </div>
  );
}

export default memo(UndoRedoButtons);
