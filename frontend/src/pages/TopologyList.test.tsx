import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import TopologyList from './TopologyList';
import type { NetworkTopology } from '../types/api';

const mockNavigate = vi.fn();

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

const storeState = {
  topologies: [] as NetworkTopology[],
  loading: false,
  error: null as string | null,
  fetchTopologies: vi.fn(),
};

vi.mock('../stores', () => ({
  useTopologyStore: (selector: (s: typeof storeState) => unknown) => selector(storeState),
}));

vi.mock('../api/client', () => ({
  apiClient: {
    deleteTopology: vi.fn(),
  },
}));

vi.mock('../utils/topologyYaml', () => ({
  downloadTopologyYaml: vi.fn(),
  parseImportedYaml: vi.fn(() => ({ topology: null, error: null })),
  readFileAsText: vi.fn(),
}));

vi.mock('./TopologyList.css', () => ({}));

describe('TopologyList', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    storeState.topologies = [];
    storeState.loading = false;
    storeState.error = null;
  });

  it('navigates to create page when create button clicked and no callback provided', async () => {
    render(
      <MemoryRouter>
        <TopologyList />
      </MemoryRouter>
    );

    await userEvent.click(screen.getByRole('button', { name: 'Create Topology' }));

    expect(mockNavigate).toHaveBeenCalledWith('/topologies/create');
  });

  it('uses callback when provided for create action', async () => {
    const onCreateTopology = vi.fn();

    render(
      <MemoryRouter>
        <TopologyList onCreateTopology={onCreateTopology} />
      </MemoryRouter>
    );

    await userEvent.click(screen.getByRole('button', { name: 'Create Topology' }));

    expect(onCreateTopology).toHaveBeenCalledTimes(1);
    expect(mockNavigate).not.toHaveBeenCalled();
  });

  it('filters topologies by search term and phase', async () => {
    storeState.topologies = [
      {
        apiVersion: 'simulation.kuro.io/v1alpha1',
        kind: 'NetworkTopology',
        metadata: {
          name: 'alpha',
          namespace: 'kuro-experiment',
          uid: 'uid-alpha',
          creationTimestamp: '2026-01-01T00:00:00Z',
        },
        spec: { nodeGroups: [] },
        status: { phase: 'Running', nodeCount: 2, readyNodes: 2 },
      },
      {
        apiVersion: 'simulation.kuro.io/v1alpha1',
        kind: 'NetworkTopology',
        metadata: {
          name: 'beta',
          namespace: 'kuro-experiment',
          uid: 'uid-beta',
          creationTimestamp: '2026-01-01T00:00:00Z',
        },
        spec: { nodeGroups: [] },
        status: { phase: 'Pending', nodeCount: 1, readyNodes: 0 },
      },
    ];

    render(
      <MemoryRouter>
        <TopologyList />
      </MemoryRouter>
    );

    expect(screen.getByText('alpha')).toBeInTheDocument();
    expect(screen.getByText('beta')).toBeInTheDocument();

    await userEvent.type(screen.getByPlaceholderText('Search topologies...'), 'alp');

    await waitFor(() => {
      expect(screen.getByText('alpha')).toBeInTheDocument();
      expect(screen.queryByText('beta')).not.toBeInTheDocument();
    });
  });
});
