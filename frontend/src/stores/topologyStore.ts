import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type {
  NetworkTopology,
  TopologyNode,
  TopologyLink,
  TrafficControl,
  TrafficPolicy,
  LinkMetrics,
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
      // Only persist selection state, not data (data should be fetched fresh)
      partialize: (state) => ({
        selectedNode: state.selectedNode,
        selectedLink: state.selectedLink,
        sidebarCollapsed: state.sidebarCollapsed,
      }),
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
