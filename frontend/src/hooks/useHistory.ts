import { useState, useCallback, useRef, useEffect } from 'react';

/**
 * History entry containing a snapshot of state
 */
interface HistoryEntry<T> {
  state: T;
  timestamp: number;
}

/**
 * Options for useHistory hook
 */
interface UseHistoryOptions {
  /** Maximum number of history entries to keep (default: 50) */
  maxHistorySize?: number;
  /** Debounce time in ms before saving a new history entry (default: 300) */
  debounceMs?: number;
}

/**
 * Return type of useHistory hook
 */
interface UseHistoryReturn<T> {
  /** Current state */
  current: T;
  /** Whether undo is available */
  canUndo: boolean;
  /** Whether redo is available */
  canRedo: boolean;
  /** Push a new state to history */
  pushState: (state: T) => void;
  /** Undo to previous state */
  undo: () => T | null;
  /** Redo to next state */
  redo: () => T | null;
  /** Reset history with initial state */
  reset: (initialState: T) => void;
  /** Clear history but keep current state */
  clearHistory: () => void;
  /** Get history size */
  historySize: number;
  /** Get current position in history (0 = oldest) */
  currentPosition: number;
}

/**
 * Check if two states are equal (shallow comparison for arrays/objects)
 */
function isEqual<T>(a: T, b: T): boolean {
  if (a === b) return true;
  if (typeof a !== 'object' || a === null || typeof b !== 'object' || b === null) {
    return a === b;
  }
  // For arrays, compare length and references
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false;
    // Quick check: if same length and same references, likely equal
    return a === b;
  }
  return false;
}

/**
 * A hook for managing undo/redo history with debouncing support.
 * 
 * @param initialState - The initial state value
 * @param options - Configuration options
 * @returns History management functions and state
 * 
 * @example
 * ```tsx
 * const { current, pushState, undo, redo, canUndo, canRedo } = useHistory(initialNodes);
 * 
 * // Save state before making changes
 * pushState(newNodes);
 * 
 * // Handle undo
 * const previousState = undo();
 * if (previousState) {
 *   setNodes(previousState);
 * }
 * ```
 */
export function useHistory<T>(
  initialState: T,
  options: UseHistoryOptions = {}
): UseHistoryReturn<T> {
  const { maxHistorySize = 50, debounceMs = 300 } = options;

  // History stack - stores all past states
  const [history, setHistory] = useState<HistoryEntry<T>[]>([
    { state: initialState, timestamp: Date.now() }
  ]);
  
  // Current position in history (index)
  const [position, setPosition] = useState(0);
  
  // Debounce timer ref
  const debounceTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  
  // Last pushed state ref (for debouncing comparison)
  const lastPushedStateRef = useRef<T>(initialState);
  
  // Position ref for callback stability
  const positionRef = useRef(position);
  
  // Keep positionRef in sync
  useEffect(() => {
    positionRef.current = position;
  }, [position]);

  /**
   * Push a new state to history
   * Uses debouncing to avoid creating too many history entries during rapid changes
   */
  const pushState = useCallback(
    (newState: T) => {
      // Clear any pending debounce timer
      if (debounceTimerRef.current) {
        clearTimeout(debounceTimerRef.current);
      }

      // Check if state is actually different (simple reference check)
      if (isEqual(newState, lastPushedStateRef.current)) {
        return;
      }

      // Debounce the state push
      debounceTimerRef.current = setTimeout(() => {
        setHistory((prevHistory) => {
          // Truncate any "future" history if we're not at the end
          const truncatedHistory = prevHistory.slice(0, positionRef.current + 1);
          
          // Add new entry - use structuredClone for better performance
          const newEntry: HistoryEntry<T> = {
            state: structuredClone(newState) as T,
            timestamp: Date.now(),
          };
          
          // Keep history within size limit
          const newHistory = [...truncatedHistory, newEntry].slice(-maxHistorySize);
          
          return newHistory;
        });
        
        setPosition((prevPosition) => {
          // Calculate new position (will be at the end)
          const newPosition = Math.min(prevPosition + 1, maxHistorySize - 1);
          return newPosition;
        });
        
        lastPushedStateRef.current = newState;
      }, debounceMs);
    },
    [debounceMs, maxHistorySize]
  );

  /**
   * Undo to previous state
   * @returns The previous state, or null if cannot undo
   */
  const undo = useCallback((): T | null => {
    if (position <= 0) {
      return null;
    }

    const newPosition = position - 1;
    setPosition(newPosition);
    
    const previousEntry = history[newPosition];
    lastPushedStateRef.current = previousEntry.state;
    
    return previousEntry.state;
  }, [history, position]);

  /**
   * Redo to next state
   * @returns The next state, or null if cannot redo
   */
  const redo = useCallback((): T | null => {
    if (position >= history.length - 1) {
      return null;
    }

    const newPosition = position + 1;
    setPosition(newPosition);
    
    const nextEntry = history[newPosition];
    lastPushedStateRef.current = nextEntry.state;
    
    return nextEntry.state;
  }, [history, position]);

  /**
   * Reset history with a new initial state
   */
  const reset = useCallback((newInitialState: T) => {
    // Clear debounce timer
    if (debounceTimerRef.current) {
      clearTimeout(debounceTimerRef.current);
    }
    
    setHistory([{ state: newInitialState, timestamp: Date.now() }]);
    setPosition(0);
    lastPushedStateRef.current = newInitialState;
  }, []);

  /**
   * Clear history but keep current state
   */
  const clearHistory = useCallback(() => {
    // Clear debounce timer
    if (debounceTimerRef.current) {
      clearTimeout(debounceTimerRef.current);
    }
    
    const currentEntry = history[position];
    if (currentEntry) {
      setHistory([currentEntry]);
      setPosition(0);
    }
  }, [history, position]);

  // Get current state
  const current = history[position]?.state ?? initialState;

  return {
    current,
    canUndo: position > 0,
    canRedo: position < history.length - 1,
    pushState,
    undo,
    redo,
    reset,
    clearHistory,
    historySize: history.length,
    currentPosition: position,
  };
}

export default useHistory;
