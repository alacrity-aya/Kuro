import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { useHistory } from '../hooks/useHistory';

describe('useHistory', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('Initial State', () => {
    it('initializes with the provided initial state', () => {
      const initialState = { value: 0 };
      const { result } = renderHook(() => useHistory(initialState));
      
      expect(result.current.current).toEqual(initialState);
    });

    it('starts with canUndo as false', () => {
      const { result } = renderHook(() => useHistory({ value: 0 }));
      
      expect(result.current.canUndo).toBe(false);
    });

    it('starts with canRedo as false', () => {
      const { result } = renderHook(() => useHistory({ value: 0 }));
      
      expect(result.current.canRedo).toBe(false);
    });

    it('starts with historySize of 1', () => {
      const { result } = renderHook(() => useHistory({ value: 0 }));
      
      expect(result.current.historySize).toBe(1);
    });

    it('starts with currentPosition of 0', () => {
      const { result } = renderHook(() => useHistory({ value: 0 }));
      
      expect(result.current.currentPosition).toBe(0);
    });
  });

  describe('pushState', () => {
    it('pushes new state to history', () => {
      const { result } = renderHook(() => useHistory({ value: 0 }));
      
      act(() => {
        result.current.pushState({ value: 1 });
        vi.runAllTimers();
      });
      
      expect(result.current.current).toEqual({ value: 1 });
      expect(result.current.canUndo).toBe(true);
    });

    it('does not push same state (reference equal)', () => {
      const state = { value: 0 };
      const { result } = renderHook(() => useHistory(state));
      
      act(() => {
        result.current.pushState(state);
        vi.runAllTimers();
      });
      
      expect(result.current.historySize).toBe(1);
    });

    it('increases history size when pushing new states', () => {
      const { result } = renderHook(() => useHistory({ value: 0 }));
      
      act(() => {
        result.current.pushState({ value: 1 });
        vi.runAllTimers();
      });
      
      act(() => {
        result.current.pushState({ value: 2 });
        vi.runAllTimers();
      });
      
      expect(result.current.historySize).toBe(3);
    });
  });

  describe('undo', () => {
    it('returns null when cannot undo', () => {
      const { result } = renderHook(() => useHistory({ value: 0 }));
      
      let undoResult;
      act(() => {
        undoResult = result.current.undo();
      });
      
      expect(undoResult).toBeNull();
    });

    it('returns previous state when can undo', () => {
      const { result } = renderHook(() => useHistory({ value: 0 }));
      
      act(() => {
        result.current.pushState({ value: 1 });
        vi.runAllTimers();
      });
      
      let undoResult;
      act(() => {
        undoResult = result.current.undo();
      });
      
      expect(undoResult).toEqual({ value: 0 });
    });

    it('updates current state after undo', () => {
      const { result } = renderHook(() => useHistory({ value: 0 }));
      
      act(() => {
        result.current.pushState({ value: 1 });
        vi.runAllTimers();
      });
      
      act(() => {
        result.current.undo();
      });
      
      expect(result.current.current).toEqual({ value: 0 });
    });

    it('sets canRedo to true after undo', () => {
      const { result } = renderHook(() => useHistory({ value: 0 }));
      
      act(() => {
        result.current.pushState({ value: 1 });
        vi.runAllTimers();
      });
      
      act(() => {
        result.current.undo();
      });
      
      expect(result.current.canRedo).toBe(true);
    });

    it('can undo multiple times', () => {
      const { result } = renderHook(() => useHistory({ value: 0 }));
      
      act(() => {
        result.current.pushState({ value: 1 });
        vi.runAllTimers();
      });
      
      act(() => {
        result.current.pushState({ value: 2 });
        vi.runAllTimers();
      });
      
      act(() => {
        result.current.undo();
      });
      
      expect(result.current.current).toEqual({ value: 1 });
      
      act(() => {
        result.current.undo();
      });
      
      expect(result.current.current).toEqual({ value: 0 });
    });
  });

  describe('redo', () => {
    it('returns null when cannot redo', () => {
      const { result } = renderHook(() => useHistory({ value: 0 }));
      
      let redoResult;
      act(() => {
        redoResult = result.current.redo();
      });
      
      expect(redoResult).toBeNull();
    });

    it('returns next state after undo', () => {
      const { result } = renderHook(() => useHistory({ value: 0 }));
      
      act(() => {
        result.current.pushState({ value: 1 });
        vi.runAllTimers();
      });
      
      act(() => {
        result.current.undo();
      });
      
      let redoResult;
      act(() => {
        redoResult = result.current.redo();
      });
      
      expect(redoResult).toEqual({ value: 1 });
    });

    it('updates current state after redo', () => {
      const { result } = renderHook(() => useHistory({ value: 0 }));
      
      act(() => {
        result.current.pushState({ value: 1 });
        vi.runAllTimers();
      });
      
      act(() => {
        result.current.undo();
      });
      
      act(() => {
        result.current.redo();
      });
      
      expect(result.current.current).toEqual({ value: 1 });
    });

    it('sets canUndo to true after redo', () => {
      const { result } = renderHook(() => useHistory({ value: 0 }));
      
      act(() => {
        result.current.pushState({ value: 1 });
        vi.runAllTimers();
      });
      
      act(() => {
        result.current.undo();
      });
      
      act(() => {
        result.current.redo();
      });
      
      expect(result.current.canUndo).toBe(true);
    });
  });

  describe('reset', () => {
    it('resets history with new initial state', () => {
      const { result } = renderHook(() => useHistory({ value: 0 }));
      
      act(() => {
        result.current.pushState({ value: 1 });
        vi.runAllTimers();
      });
      
      act(() => {
        result.current.reset({ value: 100 });
      });
      
      expect(result.current.current).toEqual({ value: 100 });
      expect(result.current.historySize).toBe(1);
      expect(result.current.canUndo).toBe(false);
      expect(result.current.canRedo).toBe(false);
    });
  });

  describe('clearHistory', () => {
    it('clears history but keeps current state', () => {
      const { result } = renderHook(() => useHistory({ value: 0 }));
      
      act(() => {
        result.current.pushState({ value: 1 });
        vi.runAllTimers();
      });
      
      act(() => {
        result.current.pushState({ value: 2 });
        vi.runAllTimers();
      });
      
      act(() => {
        result.current.clearHistory();
      });
      
      expect(result.current.current).toEqual({ value: 2 });
      expect(result.current.historySize).toBe(1);
      expect(result.current.canUndo).toBe(false);
      expect(result.current.canRedo).toBe(false);
    });
  });

  describe('Options', () => {
    it('respects maxHistorySize option', () => {
      const { result } = renderHook(() => 
        useHistory({ value: 0 }, { maxHistorySize: 3 })
      );
      
      // Push 5 states
      for (let i = 1; i <= 5; i++) {
        act(() => {
          result.current.pushState({ value: i });
          vi.runAllTimers();
        });
      }
      
      // History should be capped at 3
      expect(result.current.historySize).toBe(3);
    });

    it('respects debounceMs option', () => {
      const { result } = renderHook(() => 
        useHistory({ value: 0 }, { debounceMs: 500 })
      );
      
      act(() => {
        result.current.pushState({ value: 1 });
      });
      
      // Before debounce time
      expect(result.current.historySize).toBe(1);
      
      // After debounce time
      act(() => {
        vi.advanceTimersByTime(500);
      });
      
      expect(result.current.historySize).toBe(2);
    });
  });

  describe('History Truncation', () => {
    it('truncates future history when pushing new state after undo', () => {
      const { result } = renderHook(() => useHistory({ value: 0 }));
      
      act(() => {
        result.current.pushState({ value: 1 });
        vi.runAllTimers();
      });
      
      act(() => {
        result.current.pushState({ value: 2 });
        vi.runAllTimers();
      });
      
      // Undo to { value: 1 }
      act(() => {
        result.current.undo();
      });
      
      // Push new state
      act(() => {
        result.current.pushState({ value: 3 });
        vi.runAllTimers();
      });
      
      // Should not be able to redo to { value: 2 }
      expect(result.current.canRedo).toBe(false);
      expect(result.current.historySize).toBe(3);
    });
  });
});
