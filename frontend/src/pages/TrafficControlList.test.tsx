import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import TrafficControlList from './TrafficControlList';

const mockNavigate = vi.fn();

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

const listTrafficControlsMock = vi.fn();
const deleteTrafficControlMock = vi.fn();
const createTrafficControlMock = vi.fn();

vi.mock('../api/client', () => ({
  apiClient: {
    listTrafficControls: (...args: unknown[]) => listTrafficControlsMock(...args),
    deleteTrafficControl: (...args: unknown[]) => deleteTrafficControlMock(...args),
    createTrafficControl: (...args: unknown[]) => createTrafficControlMock(...args),
  },
}));

vi.mock('../utils/trafficControlYaml', () => ({
  exportTrafficControlToYaml: vi.fn(() => 'yaml-content'),
  downloadYaml: vi.fn(),
  parseTrafficControlYaml: vi.fn(() => ({
    metadata: { name: 'imported-tc', namespace: 'kuro-experiment' },
    spec: {
      source: { matchLabels: { role: 'drones' } },
      destination: { matchLabels: { role: 'stations' } },
      policy: { bandwidth: '10Mbps', latency: '10ms', jitter: '5ms', packetLoss: '0.1%' },
    },
  })),
  validateTrafficControlYaml: vi.fn(() => ({ valid: true, errors: [] })),
}));

vi.mock('./TrafficControlList.css', () => ({}));

describe('TrafficControlList', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(window, 'confirm').mockReturnValue(true);
  });

  it('shows inline error when delete fails instead of blocking alert', async () => {
    listTrafficControlsMock.mockResolvedValue({
      success: true,
      data: {
        items: [
          {
            apiVersion: 'simulation.kuro.io/v1alpha1',
            kind: 'TrafficControl',
            metadata: {
              name: 'tc-a',
              namespace: 'kuro-experiment',
              uid: 'uid-a',
              creationTimestamp: '2026-01-01T00:00:00Z',
            },
            spec: {
              source: { matchLabels: { 'kuro.io/node-group': 'drones' } },
              destination: { matchLabels: { 'kuro.io/node-group': 'stations' } },
              policy: { bandwidth: '10Mbps', latency: '10ms', jitter: '5ms', packetLoss: '0.1%' },
            },
            status: { phase: 'Running', appliedLinks: 1 },
          },
        ],
        totalCount: 1,
      },
    });

    deleteTrafficControlMock.mockResolvedValue({
      success: false,
      error: 'delete failed',
    });

    const alertSpy = vi.spyOn(window, 'alert').mockImplementation(() => undefined);

    render(
      <MemoryRouter>
        <TrafficControlList />
      </MemoryRouter>
    );

    await screen.findByText('tc-a');

    await userEvent.click(screen.getByRole('button', { name: 'Delete' }));

    await waitFor(() => {
      expect(screen.getByText('⚠️ delete failed')).toBeInTheDocument();
    });
    expect(alertSpy).not.toHaveBeenCalled();
  });

  it('supports retry from inline error block', async () => {
    listTrafficControlsMock
      .mockResolvedValueOnce({ success: false, error: 'load failed' })
      .mockResolvedValueOnce({
        success: true,
        data: {
          items: [],
          totalCount: 0,
        },
      });

    render(
      <MemoryRouter>
        <TrafficControlList />
      </MemoryRouter>
    );

    await screen.findByText('⚠️ load failed');
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }));

    await waitFor(() => {
      expect(listTrafficControlsMock).toHaveBeenCalledTimes(2);
    });
  });
});
