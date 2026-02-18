// Mock API Client for Kuro
// All API calls return mock data, simulating async network requests

import type {
  KuroApiClient,
  NetworkTopology,
  TrafficControl,
  TopologyNode,
  TopologyLink,
  NodeMetrics,
  LinkMetricsHistory,
  ApiResponse,
  ListResult,
} from '../types/api';

import {
  mockTopologies,
  mockTrafficControls,
  generateMockNodes,
  generateMockLinks,
  generateNodeMetrics,
  generateLinkMetricsHistory,
} from './mock';

// Simulate network delay
const delay = (ms: number = 100) => new Promise((resolve) => setTimeout(resolve, ms));

// ============================================================================
// Mock API Client Implementation
// ============================================================================

class MockKuroApiClient implements KuroApiClient {
  private topologies: NetworkTopology[] = [...mockTopologies];
  private trafficControls: TrafficControl[] = [...mockTrafficControls];

  // =========================================================================
  // Topology Operations
  // =========================================================================

  async listTopologies(namespace: string = 'default'): Promise<ApiResponse<ListResult<NetworkTopology>>> {
    await delay(150);
    
    const items = this.topologies.filter((t) => t.metadata.namespace === namespace);
    
    return {
      success: true,
      data: {
        items,
        totalCount: items.length,
      },
    };
  }

  async getTopology(name: string, namespace: string = 'default'): Promise<ApiResponse<NetworkTopology>> {
    await delay(100);
    
    const topology = this.topologies.find(
      (t) => t.metadata.name === name && t.metadata.namespace === namespace
    );
    
    if (!topology) {
      return {
        success: false,
        error: `Topology '${name}' not found in namespace '${namespace}'`,
      };
    }
    
    return { success: true, data: topology };
  }

  async createTopology(topology: NetworkTopology): Promise<ApiResponse<NetworkTopology>> {
    await delay(200);
    
    // Check if already exists
    const exists = this.topologies.find(
      (t) => t.metadata.name === topology.metadata.name && 
             t.metadata.namespace === topology.metadata.namespace
    );
    
    if (exists) {
      return {
        success: false,
        error: `Topology '${topology.metadata.name}' already exists`,
      };
    }
    
    const newTopology: NetworkTopology = {
      ...topology,
      metadata: {
        ...topology.metadata,
        uid: randomUuid(),
        creationTimestamp: new Date().toISOString(),
      },
      status: {
        phase: 'Pending',
        nodeCount: 0,
        readyNodes: 0,
      },
    };
    
    this.topologies.push(newTopology);
    
    return { success: true, data: newTopology };
  }

  async deleteTopology(name: string, namespace: string = 'default'): Promise<ApiResponse<void>> {
    await delay(150);
    
    const index = this.topologies.findIndex(
      (t) => t.metadata.name === name && t.metadata.namespace === namespace
    );
    
    if (index === -1) {
      return {
        success: false,
        error: `Topology '${name}' not found`,
      };
    }
    
    this.topologies.splice(index, 1);
    
    return { success: true };
  }

  // =========================================================================
  // TrafficControl Operations
  // =========================================================================

  async listTrafficControls(namespace: string = 'default'): Promise<ApiResponse<ListResult<TrafficControl>>> {
    await delay(150);
    
    const items = this.trafficControls.filter((t) => t.metadata.namespace === namespace);
    
    return {
      success: true,
      data: {
        items,
        totalCount: items.length,
      },
    };
  }

  async getTrafficControl(name: string, namespace: string = 'default'): Promise<ApiResponse<TrafficControl>> {
    await delay(100);
    
    const tc = this.trafficControls.find(
      (t) => t.metadata.name === name && t.metadata.namespace === namespace
    );
    
    if (!tc) {
      return {
        success: false,
        error: `TrafficControl '${name}' not found`,
      };
    }
    
    return { success: true, data: tc };
  }

  async createTrafficControl(tc: TrafficControl): Promise<ApiResponse<TrafficControl>> {
    await delay(200);
    
    const exists = this.trafficControls.find(
      (t) => t.metadata.name === tc.metadata.name && 
             t.metadata.namespace === tc.metadata.namespace
    );
    
    if (exists) {
      return {
        success: false,
        error: `TrafficControl '${tc.metadata.name}' already exists`,
      };
    }
    
    const newTc: TrafficControl = {
      ...tc,
      metadata: {
        ...tc.metadata,
        uid: randomUuid(),
        creationTimestamp: new Date().toISOString(),
      },
      status: {
        phase: 'Pending',
        appliedLinks: 0,
      },
    };
    
    this.trafficControls.push(newTc);
    
    return { success: true, data: newTc };
  }

  async updateTrafficControl(tc: TrafficControl): Promise<ApiResponse<TrafficControl>> {
    await delay(200);
    
    const index = this.trafficControls.findIndex(
      (t) => t.metadata.name === tc.metadata.name && 
             t.metadata.namespace === tc.metadata.namespace
    );
    
    if (index === -1) {
      return {
        success: false,
        error: `TrafficControl '${tc.metadata.name}' not found`,
      };
    }
    
    this.trafficControls[index] = {
      ...tc,
      status: {
        phase: 'Running',
        appliedLinks: tc.status?.appliedLinks ?? 0,
        conditions: tc.status?.conditions,
      },
    };
    
    return { success: true, data: this.trafficControls[index] };
  }

  async deleteTrafficControl(name: string, namespace: string = 'default'): Promise<ApiResponse<void>> {
    await delay(150);
    
    const index = this.trafficControls.findIndex(
      (t) => t.metadata.name === name && t.metadata.namespace === namespace
    );
    
    if (index === -1) {
      return {
        success: false,
        error: `TrafficControl '${name}' not found`,
      };
    }
    
    this.trafficControls.splice(index, 1);
    
    return { success: true };
  }

  // =========================================================================
  // Topology Visualization
  // =========================================================================

  async getTopologyNodes(topologyName: string, namespace: string = 'default'): Promise<ApiResponse<TopologyNode[]>> {
    await delay(200);
    
    const topology = this.topologies.find(
      (t) => t.metadata.name === topologyName && t.metadata.namespace === namespace
    );
    
    if (!topology) {
      return {
        success: false,
        error: `Topology '${topologyName}' not found`,
      };
    }
    
    const nodes = generateMockNodes(topology);
    
    return { success: true, data: nodes };
  }

  async getTopologyLinks(topologyName: string, namespace: string = 'default'): Promise<ApiResponse<TopologyLink[]>> {
    await delay(200);
    
    const topology = this.topologies.find(
      (t) => t.metadata.name === topologyName && t.metadata.namespace === namespace
    );
    
    if (!topology) {
      return {
        success: false,
        error: `Topology '${topologyName}' not found`,
      };
    }
    
    const nodes = generateMockNodes(topology);
    const links = generateMockLinks(nodes, this.trafficControls);
    
    return { success: true, data: links };
  }

  // =========================================================================
  // Metrics
  // =========================================================================

  async getNodeMetrics(nodeId: string): Promise<ApiResponse<NodeMetrics>> {
    await delay(100);
    
    const metrics = generateNodeMetrics(nodeId);
    
    return { success: true, data: metrics };
  }

  async getLinkMetrics(linkId: string): Promise<ApiResponse<LinkMetricsHistory>> {
    await delay(100);
    
    const metrics = generateLinkMetricsHistory(linkId);
    
    return { success: true, data: metrics };
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

function randomUuid(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

// ============================================================================
// Export Singleton Instance
// ============================================================================

export const apiClient: KuroApiClient = new MockKuroApiClient();

// Also export the class for testing
export { MockKuroApiClient };
