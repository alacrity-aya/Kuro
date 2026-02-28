// Kuro API Client
// Supports both mock and real API backends based on VITE_USE_MOCK_API

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

// Environment configuration
const USE_MOCK_API = import.meta.env.VITE_USE_MOCK_API !== 'false'; // Default to mock
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api/v1';

// Simulate network delay (for mock)
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

  async listTopologies(namespace: string = 'kuro-experiment'): Promise<ApiResponse<ListResult<NetworkTopology>>> {
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

  async getTopology(name: string, namespace: string = 'kuro-experiment'): Promise<ApiResponse<NetworkTopology>> {
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

  async updateTopology(topology: NetworkTopology): Promise<ApiResponse<NetworkTopology>> {
    await delay(200);

    const index = this.topologies.findIndex(
      (t) => t.metadata.name === topology.metadata.name &&
        t.metadata.namespace === topology.metadata.namespace
    );

    if (index === -1) {
      return {
        success: false,
        error: `Topology '${topology.metadata.name}' not found`,
      };
    }

    // Update the topology while preserving metadata
    const updatedTopology: NetworkTopology = {
      ...topology,
      metadata: {
        ...this.topologies[index].metadata,
        labels: topology.metadata.labels,
      },
      status: this.topologies[index].status,
    };

    this.topologies[index] = updatedTopology;

    return { success: true, data: updatedTopology };
  }

  async deleteTopology(name: string, namespace: string = 'kuro-experiment'): Promise<ApiResponse<void>> {
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

    // Collect all label values from the topology's node groups
    const topology = this.topologies[index];
    const topologyLabelValues = new Set<string>();
    topology.spec.nodeGroups?.forEach((group) => {
      // Collect role labels and node-group names used by TrafficControls
      if (group.labels) {
        Object.values(group.labels).forEach((v) => topologyLabelValues.add(v));
      }
      if (group.name) {
        topologyLabelValues.add(group.name);
      }
    });

    // Cascade delete: remove TCs in the same namespace whose source or destination
    // matchLabels values are all contained within the topology's label values
    this.trafficControls = this.trafficControls.filter((tc) => {
      if (tc.metadata.namespace !== namespace) return true;

      const srcValues = Object.values(tc.spec.source.matchLabels);
      const dstValues = Object.values(tc.spec.destination.matchLabels);
      const allTcValues = [...srcValues, ...dstValues];

      // If all label values of this TC match the topology's label values, delete it
      const shouldDelete = allTcValues.length > 0 && allTcValues.every((v) => topologyLabelValues.has(v));
      return !shouldDelete;
    });

    this.topologies.splice(index, 1);

    return { success: true };
  }

  // =========================================================================
  // TrafficControl Operations
  // =========================================================================

  async listTrafficControls(namespace: string = 'kuro-experiment'): Promise<ApiResponse<ListResult<TrafficControl>>> {
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

  async getTrafficControl(name: string, namespace: string = 'kuro-experiment'): Promise<ApiResponse<TrafficControl>> {
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

  async deleteTrafficControl(name: string, namespace: string = 'kuro-experiment'): Promise<ApiResponse<void>> {
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

  async getTopologyNodes(topologyName: string, namespace: string = 'kuro-experiment'): Promise<ApiResponse<TopologyNode[]>> {
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

  async getTopologyLinks(topologyName: string, namespace: string = 'kuro-experiment'): Promise<ApiResponse<TopologyLink[]>> {
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
// Real API Client Implementation
// ============================================================================

class RealKuroApiClient implements KuroApiClient {
  private async request<T>(
    method: string,
    path: string,
    body?: unknown
  ): Promise<ApiResponse<T>> {
    const url = `${API_BASE_URL}${path}`;
    const options: RequestInit = {
      method,
      headers: {
        'Content-Type': 'application/json',
      },
    };

    if (body) {
      options.body = JSON.stringify(body);
    }

    try {
      const response = await fetch(url, options);
      const data = await response.json();
      return data as ApiResponse<T>;
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Network error',
      };
    }
  }

  // =========================================================================
  // Topology Operations
  // =========================================================================

  async listTopologies(namespace: string = 'kuro-experiment'): Promise<ApiResponse<ListResult<NetworkTopology>>> {
    return this.request<ListResult<NetworkTopology>>('GET', `/namespaces/${namespace}/networktopologies`);
  }

  async getTopology(name: string, namespace: string = 'kuro-experiment'): Promise<ApiResponse<NetworkTopology>> {
    return this.request<NetworkTopology>('GET', `/namespaces/${namespace}/networktopologies/${name}`);
  }

  async createTopology(topology: NetworkTopology): Promise<ApiResponse<NetworkTopology>> {
    const body = {
      name: topology.metadata.name,
      labels: topology.metadata.labels,
      spec: topology.spec,
    };
    return this.request<NetworkTopology>('POST', `/namespaces/${topology.metadata.namespace}/networktopologies`, body);
  }

  async updateTopology(topology: NetworkTopology): Promise<ApiResponse<NetworkTopology>> {
    const body = {
      name: topology.metadata.name,
      labels: topology.metadata.labels,
      spec: topology.spec,
    };
    return this.request<NetworkTopology>('PUT', `/namespaces/${topology.metadata.namespace}/networktopologies/${topology.metadata.name}`, body);
  }

  async deleteTopology(name: string, namespace: string = 'kuro-experiment'): Promise<ApiResponse<void>> {
    return this.request<void>('DELETE', `/namespaces/${namespace}/networktopologies/${name}`);
  }

  // =========================================================================
  // TrafficControl Operations
  // =========================================================================

  async listTrafficControls(namespace: string = 'kuro-experiment'): Promise<ApiResponse<ListResult<TrafficControl>>> {
    return this.request<ListResult<TrafficControl>>('GET', `/namespaces/${namespace}/trafficcontrols`);
  }

  async getTrafficControl(name: string, namespace: string = 'kuro-experiment'): Promise<ApiResponse<TrafficControl>> {
    return this.request<TrafficControl>('GET', `/namespaces/${namespace}/trafficcontrols/${name}`);
  }

  async createTrafficControl(tc: TrafficControl): Promise<ApiResponse<TrafficControl>> {
    const body = {
      name: tc.metadata.name,
      labels: tc.metadata.labels,
      spec: tc.spec,
    };
    return this.request<TrafficControl>('POST', `/namespaces/${tc.metadata.namespace}/trafficcontrols`, body);
  }

  async updateTrafficControl(tc: TrafficControl): Promise<ApiResponse<TrafficControl>> {
    const body = { spec: tc.spec };
    return this.request<TrafficControl>('PUT', `/namespaces/${tc.metadata.namespace}/trafficcontrols/${tc.metadata.name}`, body);
  }

  async deleteTrafficControl(name: string, namespace: string = 'kuro-experiment'): Promise<ApiResponse<void>> {
    return this.request<void>('DELETE', `/namespaces/${namespace}/trafficcontrols/${name}`);
  }

  // =========================================================================
  // Topology Visualization
  // =========================================================================

  async getTopologyNodes(topologyName: string, namespace: string = 'kuro-experiment'): Promise<ApiResponse<TopologyNode[]>> {
    return this.request<TopologyNode[]>('GET', `/namespaces/${namespace}/topologies/${topologyName}/nodes`);
  }

  async getTopologyLinks(topologyName: string, namespace: string = 'kuro-experiment'): Promise<ApiResponse<TopologyLink[]>> {
    return this.request<TopologyLink[]>('GET', `/namespaces/${namespace}/topologies/${topologyName}/links`);
  }

  // =========================================================================
  // Metrics
  // =========================================================================

  async getNodeMetrics(_nodeId: string): Promise<ApiResponse<NodeMetrics>> {
    // TODO: Implement real metrics endpoint when available
    return { success: false, error: 'Metrics API not implemented' };
  }

  async getLinkMetrics(_linkId: string): Promise<ApiResponse<LinkMetricsHistory>> {
    // TODO: Implement real metrics endpoint when available
    return { success: false, error: 'Metrics API not implemented' };
  }
}

// ============================================================================
// Export Singleton Instance
// ============================================================================

// Use mock or real API based on environment variable
export const apiClient: KuroApiClient = USE_MOCK_API
  ? new MockKuroApiClient()
  : new RealKuroApiClient();

// Also export classes for testing
export { MockKuroApiClient, RealKuroApiClient };
