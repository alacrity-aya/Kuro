import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import UndoRedoButtons from './UndoRedoButtons';

describe('UndoRedoButtons', () => {
  describe('Rendering', () => {
    it('renders undo and redo buttons', () => {
      render(<UndoRedoButtons canUndo={false} canRedo={false} onUndo={vi.fn()} onRedo={vi.fn()} />);
      
      const buttons = screen.getAllByRole('button');
      expect(buttons).toHaveLength(2);
    });

    it('disables undo button when canUndo is false', () => {
      render(<UndoRedoButtons canUndo={false} canRedo={false} onUndo={vi.fn()} onRedo={vi.fn()} />);
      
      const buttons = screen.getAllByRole('button');
      expect(buttons[0]).toBeDisabled();
    });

    it('disables redo button when canRedo is false', () => {
      render(<UndoRedoButtons canUndo={false} canRedo={false} onUndo={vi.fn()} onRedo={vi.fn()} />);
      
      const buttons = screen.getAllByRole('button');
      expect(buttons[1]).toBeDisabled();
    });

    it('enables undo button when canUndo is true', () => {
      render(<UndoRedoButtons canUndo canRedo={false} onUndo={vi.fn()} onRedo={vi.fn()} />);
      
      const buttons = screen.getAllByRole('button');
      expect(buttons[0]).not.toBeDisabled();
    });

    it('enables redo button when canRedo is true', () => {
      render(<UndoRedoButtons canUndo={false} canRedo onUndo={vi.fn()} onRedo={vi.fn()} />);
      
      const buttons = screen.getAllByRole('button');
      expect(buttons[1]).not.toBeDisabled();
    });

    it('applies custom className', () => {
      const { container } = render(
        <UndoRedoButtons
          canUndo={false}
          canRedo={false}
          onUndo={vi.fn()}
          onRedo={vi.fn()}
          className="custom-class"
        />
      );
      
      expect(container.firstChild).toHaveClass('undo-redo-buttons', 'custom-class');
    });
  });

  describe('Click Interactions', () => {
    it('calls onUndo when undo button is clicked', async () => {
      const user = userEvent.setup();
      const handleUndo = vi.fn();
      
      render(
        <UndoRedoButtons
          canUndo
          canRedo={false}
          onUndo={handleUndo}
          onRedo={vi.fn()}
        />
      );
      
      const buttons = screen.getAllByRole('button');
      await user.click(buttons[0]);
      
      expect(handleUndo).toHaveBeenCalledTimes(1);
    });

    it('calls onRedo when redo button is clicked', async () => {
      const user = userEvent.setup();
      const handleRedo = vi.fn();
      
      render(
        <UndoRedoButtons
          canUndo={false}
          canRedo
          onUndo={vi.fn()}
          onRedo={handleRedo}
        />
      );
      
      const buttons = screen.getAllByRole('button');
      await user.click(buttons[1]);
      
      expect(handleRedo).toHaveBeenCalledTimes(1);
    });

    it('does not call onUndo when undo is disabled', async () => {
      const user = userEvent.setup();
      const handleUndo = vi.fn();
      
      render(
        <UndoRedoButtons
          canUndo={false}
          canRedo={false}
          onUndo={handleUndo}
          onRedo={vi.fn()}
        />
      );
      
      const buttons = screen.getAllByRole('button');
      await user.click(buttons[0]);
      
      expect(handleUndo).not.toHaveBeenCalled();
    });

    it('does not call onRedo when redo is disabled', async () => {
      const user = userEvent.setup();
      const handleRedo = vi.fn();
      
      render(
        <UndoRedoButtons
          canUndo={false}
          canRedo={false}
          onUndo={vi.fn()}
          onRedo={handleRedo}
        />
      );
      
      const buttons = screen.getAllByRole('button');
      await user.click(buttons[1]);
      
      expect(handleRedo).not.toHaveBeenCalled();
    });
  });

  describe('Keyboard Shortcuts', () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it('triggers undo on Ctrl+Z', async () => {
      const handleUndo = vi.fn();
      
      render(
        <UndoRedoButtons
          canUndo
          canRedo={false}
          onUndo={handleUndo}
          onRedo={vi.fn()}
        />
      );
      
      fireEvent.keyDown(window, { key: 'z', ctrlKey: true });
      
      expect(handleUndo).toHaveBeenCalledTimes(1);
    });

    it('triggers undo on Cmd+Z (metaKey)', async () => {
      const handleUndo = vi.fn();
      
      render(
        <UndoRedoButtons
          canUndo
          canRedo={false}
          onUndo={handleUndo}
          onRedo={vi.fn()}
        />
      );
      
      fireEvent.keyDown(window, { key: 'z', metaKey: true });
      
      expect(handleUndo).toHaveBeenCalledTimes(1);
    });

    it('triggers redo on Ctrl+Shift+Z', async () => {
      const handleRedo = vi.fn();
      
      render(
        <UndoRedoButtons
          canUndo={false}
          canRedo
          onUndo={vi.fn()}
          onRedo={handleRedo}
        />
      );
      
      fireEvent.keyDown(window, { key: 'z', ctrlKey: true, shiftKey: true });
      
      expect(handleRedo).toHaveBeenCalledTimes(1);
    });

    it('triggers redo on Ctrl+Y', async () => {
      const handleRedo = vi.fn();
      
      render(
        <UndoRedoButtons
          canUndo={false}
          canRedo
          onUndo={vi.fn()}
          onRedo={handleRedo}
        />
      );
      
      fireEvent.keyDown(window, { key: 'y', ctrlKey: true });
      
      expect(handleRedo).toHaveBeenCalledTimes(1);
    });

    it('does not trigger undo when canUndo is false', async () => {
      const handleUndo = vi.fn();
      
      render(
        <UndoRedoButtons
          canUndo={false}
          canRedo={false}
          onUndo={handleUndo}
          onRedo={vi.fn()}
        />
      );
      
      fireEvent.keyDown(window, { key: 'z', ctrlKey: true });
      
      expect(handleUndo).not.toHaveBeenCalled();
    });

    it('does not trigger redo when canRedo is false', async () => {
      const handleRedo = vi.fn();
      
      render(
        <UndoRedoButtons
          canUndo={false}
          canRedo={false}
          onUndo={vi.fn()}
          onRedo={handleRedo}
        />
      );
      
      fireEvent.keyDown(window, { key: 'y', ctrlKey: true });
      
      expect(handleRedo).not.toHaveBeenCalled();
    });

    it('can disable keyboard shortcuts', async () => {
      const handleUndo = vi.fn();
      const handleRedo = vi.fn();
      
      render(
        <UndoRedoButtons
          canUndo
          canRedo
          onUndo={handleUndo}
          onRedo={handleRedo}
          enableShortcuts={false}
        />
      );
      
      fireEvent.keyDown(window, { key: 'z', ctrlKey: true });
      fireEvent.keyDown(window, { key: 'y', ctrlKey: true });
      
      expect(handleUndo).not.toHaveBeenCalled();
      expect(handleRedo).not.toHaveBeenCalled();
    });
  });

  describe('Accessibility', () => {
    it('has aria-label for undo button', () => {
      render(<UndoRedoButtons canUndo canRedo={false} onUndo={vi.fn()} onRedo={vi.fn()} />);
      
      const buttons = screen.getAllByRole('button');
      expect(buttons[0]).toHaveAttribute('aria-label', 'Undo');
    });

    it('has aria-label for redo button', () => {
      render(<UndoRedoButtons canUndo={false} canRedo onUndo={vi.fn()} onRedo={vi.fn()} />);
      
      const buttons = screen.getAllByRole('button');
      expect(buttons[1]).toHaveAttribute('aria-label', 'Redo');
    });

    it('has title attribute showing keyboard shortcut for undo', () => {
      render(<UndoRedoButtons canUndo canRedo={false} onUndo={vi.fn()} onRedo={vi.fn()} />);
      
      const buttons = screen.getAllByRole('button');
      expect(buttons[0]).toHaveAttribute('title', 'Undo (Ctrl+Z)');
    });

    it('has title attribute showing keyboard shortcut for redo', () => {
      render(<UndoRedoButtons canUndo={false} canRedo onUndo={vi.fn()} onRedo={vi.fn()} />);
      
      const buttons = screen.getAllByRole('button');
      expect(buttons[1]).toHaveAttribute('title', 'Redo (Ctrl+Shift+Z)');
    });

    it('has appropriate title when disabled', () => {
      render(<UndoRedoButtons canUndo={false} canRedo={false} onUndo={vi.fn()} onRedo={vi.fn()} />);
      
      const buttons = screen.getAllByRole('button');
      expect(buttons[0]).toHaveAttribute('title', 'No history to undo');
      expect(buttons[1]).toHaveAttribute('title', 'No history to redo');
    });
  });
});
