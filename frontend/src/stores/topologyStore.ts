import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { useShallow } from 'zustand/react/shallow';
import type {
  NetworkTopology,
  TopologyNode,
  TopologyLink,
  TrafficControl,
  TrafficPolicy,
  LinkMetrics,
  TSNConfig,
  TimeSyncStatus,
} from '../types/api';
import { apiClient } from '../api/client';

// ============================================================================
// Store Types
// ============================================================================

interface TopologyState {
  // Data
  topologies: NetworkTopology[];
  currentTopology: NetworkTopology | null;
  nodes: TopologyNode[];
  links: TopologyLink[];
  trafficControls: TrafficControl[];
  
  // Selection
  selectedNode: TopologyNode | null;
  selectedLink: TopologyLink | null;
  
  // UI State
  sidebarCollapsed: boolean;
  loading: boolean;
  error: string | null;
  
  // Local View
  localViewNodeId: string | null;
  
  // TSN Mode
  tsnConfig: TSNConfig;
  timeSyncStatuses: TimeSyncStatus[];
  
  // Actions - Data
  fetchTopologies: (namespace?: string) => Promise<void>;
  fetchTopology: (name: string, namespace?: string) => Promise<void>;
  fetchTopologyNodes: (name: string, namespace?: string) => Promise<void>;
  fetchTopologyLinks: (name: string, namespace?: string) => Promise<void>;
  fetchTrafficControls: (namespace?: string) => Promise<void>;
  setCurrentTopology: (topology: NetworkTopology | null) => void;
  
  // Actions - Selection
  selectNode: (node: TopologyNode | null) => void;
  selectLink: (link: TopologyLink | null) => void;
  clearSelection: () => void;
  
  // Actions - UI
  toggleSidebar: () => void;
  setSidebarCollapsed: (collapsed: boolean) => void;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  
  // Actions - Local View
  enterLocalView: (nodeId: string) => void;
  exitLocalView: () => void;
  
  // Actions - TSN Mode
  setTsnEnabled: (enabled: boolean) => void;
  setTsnConfig: (config: Partial<TSNConfig>) => void;
  setTimeSyncStatuses: (statuses: TimeSyncStatus[]) => void;
  
  // Actions - Updates
  updateLinkPolicy: (linkId: string, policy: TrafficPolicy) => void;
  updateNodeStatus: (nodeId: string, status: TopologyNode['status']) => void;
  
  // Actions - Reset
  reset: () => void;
}

// ============================================================================
// Initial State
// ============================================================================

const initialState = {
  // Data
  topologies: [],
  currentTopology: null,
  nodes: [],
  links: [],
  trafficControls: [],
  
  // Selection
  selectedNode: null,
  selectedLink: null,
  
  // UI State
  sidebarCollapsed: false,
  loading: false,
  error: null,
  
  // Local View
  localViewNodeId: null,
  
  // TSN Mode
  tsnConfig: {
    enabled: false,
    cycleTime: 100000, // 100ms in microseconds
    syncInterval: 125, // PTP default sync interval in ms
  } as TSNConfig,
  timeSyncStatuses: [] as TimeSyncStatus[],
};

// ============================================================================
// Store Implementation
// ============================================================================

export const useTopologyStore = create<TopologyState>()(
  persist(
    (set) => ({
      ...initialState,
      
      // ========================================================================
      // Data Actions
      // ========================================================================
      
      fetchTopologies: async (namespace = 'default') => {
        set({ loading: true, error: null });
        try {
          const response = await apiClient.listTopologies(namespace);
          if (response.success && response.data) {
            set({ topologies: response.data.items, loading: false });
          } else {
            set({ error: response.error ?? 'Failed to fetch topologies', loading: false });
          }
        } catch (error) {
          set({ 
            error: error instanceof Error ? error.message : 'Failed to fetch topologies', 
            loading: false 
          });
        }
      },
      
      fetchTopology: async (name, namespace = 'default') => {
        set({ loading: true, error: null });
        try {
          const response = await apiClient.getTopology(name, namespace);
          if (response.success && response.data) {
            set({ currentTopology: response.data, loading: false });
          } else {
            set({ error: response.error ?? 'Topology not found', loading: false });
          }
        } catch (error) {
          set({ 
            error: error instanceof Error ? error.message : 'Failed to fetch topology', 
            loading: false 
          });
        }
      },
      
      fetchTopologyNodes: async (name, namespace = 'default') => {
        try {
          const response = await apiClient.getTopologyNodes(name, namespace);
          if (response.success && response.data) {
            set({ nodes: response.data });
          }
        } catch (error) {
          console.error('Failed to fetch nodes:', error);
        }
      },
      
      fetchTopologyLinks: async (name, namespace = 'default') => {
        try {
          const response = await apiClient.getTopologyLinks(name, namespace);
          if (response.success && response.data) {
            set({ links: response.data });
          }
        } catch (error) {
          console.error('Failed to fetch links:', error);
        }
      },
      
      fetchTrafficControls: async (namespace = 'default') => {
        try {
          const response = await apiClient.listTrafficControls(namespace);
          if (response.success && response.data) {
            set({ trafficControls: response.data.items });
          }
        } catch (error) {
          console.error('Failed to fetch traffic controls:', error);
        }
      },
      
      setCurrentTopology: (topology) => {
        set({ currentTopology: topology });
      },
      
      // ========================================================================
      // Selection Actions
      // ========================================================================
      
      selectNode: (node) => {
        set({ selectedNode: node, selectedLink: null });
      },
      
      selectLink: (link) => {
        set({ selectedLink: link, selectedNode: null });
      },
      
      clearSelection: () => {
        set({ selectedNode: null, selectedLink: null });
      },
      
      // ========================================================================
      // UI Actions
      // ========================================================================
      
      toggleSidebar: () => {
        set((state) => ({ sidebarCollapsed: !state.sidebarCollapsed }));
      },
      
      setSidebarCollapsed: (collapsed) => {
        set({ sidebarCollapsed: collapsed });
      },
      
      setLoading: (loading) => {
        set({ loading });
      },
      
      setError: (error) => {
        set({ error });
      },
      
      // ========================================================================
      // Local View Actions
      // ========================================================================
      
      enterLocalView: (nodeId) => {
        set({ localViewNodeId: nodeId });
      },
      
      exitLocalView: () => {
        set({ localViewNodeId: null });
      },
      
      // ========================================================================
      // TSN Mode Actions
      // ========================================================================
      
      setTsnEnabled: (enabled) => {
        set((state) => ({
          tsnConfig: { ...state.tsnConfig, enabled },
        }));
      },
      
      setTsnConfig: (config) => {
        set((state) => ({
          tsnConfig: { ...state.tsnConfig, ...config },
        }));
      },
      
      setTimeSyncStatuses: (statuses) => {
        set({ timeSyncStatuses: statuses });
      },
      
      // ========================================================================
      // Update Actions
      // ========================================================================
      
      updateLinkPolicy: (linkId, policy) => {
        set((state) => ({
          links: state.links.map((link) =>
            link.id === linkId ? { ...link, policy } : link
          ),
        }));
      },
      
      updateNodeStatus: (nodeId, status) => {
        set((state) => ({
          nodes: state.nodes.map((node) =>
            node.id === nodeId ? { ...node, status } : node
          ),
        }));
      },
      
      // ========================================================================
      // Reset
      // ========================================================================
      
      reset: () => {
        set(initialState);
      },
    }),
    {
      name: 'kuro-topology-store',
      version: 1,
      // Only persist UI preferences, not data (data should be fetched fresh)
      // This reduces storage size and prevents stale data issues
      partialize: (state) => ({
        sidebarCollapsed: state.sidebarCollapsed,
        tsnConfig: state.tsnConfig,
      }),
      // Migrate from older versions if needed
      migrate: (persistedState: unknown, version: number) => {
        if (version === 0) {
          // Version 0 persisted selectedNode/selectedLink/localViewNodeId
          // We no longer persist these, return only what we need
          const state = persistedState as Record<string, unknown>;
          return {
            sidebarCollapsed: state.sidebarCollapsed ?? false,
            tsnConfig: state.tsnConfig ?? initialState.tsnConfig,
          };
        }
        return persistedState as Partial<TopologyState>;
      },
    }
  )
);

// ============================================================================
// Convenience Hooks
// ============================================================================

/**
 * Hook for loading full topology data (topology + nodes + links + traffic controls)
 */
export function useLoadTopology(name: string, namespace = 'default') {
  const { 
    fetchTopology, 
    fetchTopologyNodes, 
    fetchTopologyLinks, 
    fetchTrafficControls,
    loading,
    error,
  } = useTopologyStore();
  
  const loadAll = async () => {
    await Promise.all([
      fetchTopology(name, namespace),
      fetchTopologyNodes(name, namespace),
      fetchTopologyLinks(name, namespace),
      fetchTrafficControls(namespace),
    ]);
  };
  
  return { loadAll, loading, error };
}

/**
 * Hook for selected link with metrics
 */
export function useSelectedLinkWithMetrics() {
  const selectedLink = useTopologyStore((state) => state.selectedLink);
  
  // In a real app, this would fetch metrics from an API
  // For now, we use the metrics from the link object
  const metrics: LinkMetrics | null = selectedLink?.metrics ?? null;
  
  return { link: selectedLink, metrics };
}

/**
 * Hook for topology statistics
 */
export function useTopologyStats() {
  const { nodes, links } = useTopologyStore();
  
  return {
    totalNodes: nodes.length,
    runningNodes: nodes.filter((n) => n.status === 'running').length,
    totalLinks: links.length,
    activeLinks: links.filter((l) => l.status === 'active').length,
  };
}

/**
 * Hook for local view - filters nodes and links to show only selected node and its connections
 */
export function useLocalView() {
  const nodes = useTopologyStore((state) => state.nodes);
  const links = useTopologyStore((state) => state.links);
  const localViewNodeId = useTopologyStore((state) => state.localViewNodeId);
  
  if (!localViewNodeId) {
    return { nodes, links, isInLocalView: false, localViewNode: null };
  }
  
  const localViewNode = nodes.find((n) => n.id === localViewNodeId) ?? null;
  
  // Find all links connected to this node
  const connectedLinks = links.filter(
    (link) => link.sourceId === localViewNodeId || link.targetId === localViewNodeId
  );
  
  // Find all node IDs connected to this node
  const connectedNodeIds = new Set<string>([localViewNodeId]);
  connectedLinks.forEach((link) => {
    connectedNodeIds.add(link.sourceId);
    connectedNodeIds.add(link.targetId);
  });
  
  // Filter nodes to show only the local view node and its direct neighbors
  const filteredNodes = nodes.filter((node) => connectedNodeIds.has(node.id));
  
  return {
    nodes: filteredNodes,
    links: connectedLinks,
    isInLocalView: true,
    localViewNode,
  };
}

// ============================================================================
// Optimized Selectors with useShallow
// ============================================================================

/**
 * Hook for topology data (batch selector to reduce re-renders)
 * Returns all topology-related data with shallow comparison
 */
export function useTopologyData() {
  return useTopologyStore(
    useShallow((state: TopologyState) => ({
      topology: state.currentTopology,
      nodes: state.nodes,
      links: state.links,
      trafficControls: state.trafficControls,
      loading: state.loading,
      error: state.error,
    }))
  );
}

/**
 * Hook for selection state (batch selector)
 */
export function useTopologySelection() {
  return useTopologyStore(
    useShallow((state: TopologyState) => ({
      selectedNode: state.selectedNode,
      selectedLink: state.selectedLink,
    }))
  );
}

/**
 * Hook for UI state (batch selector)
 */
export function useTopologyUI() {
  return useTopologyStore(
    useShallow((state: TopologyState) => ({
      sidebarCollapsed: state.sidebarCollapsed,
      localViewNodeId: state.localViewNodeId,
      tsnConfig: state.tsnConfig,
    }))
  );
}

/**
 * Hook for all topology actions (stable reference)
 * Returns action functions that don't change on state updates
 */
export function useTopologyActions() {
  return useTopologyStore(
    useShallow((state: TopologyState) => ({
      fetchTopology: state.fetchTopology,
      fetchTopologyNodes: state.fetchTopologyNodes,
      fetchTopologyLinks: state.fetchTopologyLinks,
      fetchTrafficControls: state.fetchTrafficControls,
      selectNode: state.selectNode,
      selectLink: state.selectLink,
      clearSelection: state.clearSelection,
      setSidebarCollapsed: state.setSidebarCollapsed,
      updateLinkPolicy: state.updateLinkPolicy,
      exitLocalView: state.exitLocalView,
      setTsnEnabled: state.setTsnEnabled,
    }))
  );
}

/**
 * Hook for node actions only
 */
export function useNodeActions() {
  return useTopologyStore(
    useShallow((state: TopologyState) => ({
      selectNode: state.selectNode,
      clearSelection: state.clearSelection,
      enterLocalView: state.enterLocalView,
    }))
  );
}

/**
 * Hook for link actions only
 */
export function useLinkActions() {
  return useTopologyStore(
    useShallow((state: TopologyState) => ({
      selectLink: state.selectLink,
      clearSelection: state.clearSelection,
      updateLinkPolicy: state.updateLinkPolicy,
    }))
  );
}
