// Mock Data Generators for Kuro API
import type {
  NetworkTopology,
  TrafficControl,
  TopologyNode,
  TopologyLink,
  NodeRole,
  LinkMetrics,
  NodeMetrics,
  LinkMetricsHistory,
  TimeSeriesPoint,
} from '../types/api';

// ============================================================================
// Helper Functions
// ============================================================================

const randomInt = (min: number, max: number) => Math.floor(Math.random() * (max - min + 1)) + min;
const randomFloat = (min: number, max: number) => Math.random() * (max - min) + min;
const randomIp = () => `10.${randomInt(0, 255)}.${randomInt(0, 255)}.${randomInt(1, 254)}`;

const generateTimeSeries = (
  count: number,
  baseValue: number,
  variance: number,
  intervalMs: number = 60000
): TimeSeriesPoint[] => {
  const now = Date.now();
  return Array.from({ length: count }, (_, i) => ({
    timestamp: now - (count - i - 1) * intervalMs,
    value: baseValue + randomFloat(-variance, variance),
  }));
};

// ============================================================================
// Mock Topologies
// ============================================================================

export const mockTopologies: NetworkTopology[] = [
  {
    apiVersion: 'simulation.kuro.io/v1alpha1',
    kind: 'NetworkTopology',
    metadata: {
      name: 'drone-swarm-demo',
      namespace: 'kuro-experiment',
      uid: 'topo-001',
      creationTimestamp: '2026-02-18T10:00:00Z',
      labels: { environment: 'demo' },
    },
    spec: {
      nodeGroups: [
        { name: 'drones', replicas: 5, image: 'kuro/node:latest', labels: { role: 'drone' } },
        { name: 'ground', replicas: 2, image: 'kuro/node:latest', labels: { role: 'ground-station' } },
      ],
    },
    status: {
      phase: 'Running',
      nodeCount: 7,
      readyNodes: 7,
    },
  },
  {
    apiVersion: 'simulation.kuro.io/v1alpha1',
    kind: 'NetworkTopology',
    metadata: {
      name: 'iot-network',
      namespace: 'kuro-experiment',
      uid: 'topo-002',
      creationTimestamp: '2026-02-17T14:30:00Z',
      labels: { environment: 'testing' },
    },
    spec: {
      nodeGroups: [
        { name: 'sensors', replicas: 10, image: 'kuro/sensor:latest', labels: { role: 'client' } },
        { name: 'gateways', replicas: 3, image: 'kuro/gateway:latest', labels: { role: 'gateway' } },
        { name: 'servers', replicas: 2, image: 'kuro/server:latest', labels: { role: 'server' } },
      ],
    },
    status: {
      phase: 'Running',
      nodeCount: 15,
      readyNodes: 14,
    },
  },
];

// ============================================================================
// Mock TrafficControls
// ============================================================================

export const mockTrafficControls: TrafficControl[] = [
  {
    apiVersion: 'simulation.kuro.io/v1alpha1',
    kind: 'TrafficControl',
    metadata: {
      name: 'drone-to-ground',
      namespace: 'kuro-experiment',
      uid: 'tc-001',
      creationTimestamp: '2026-02-18T10:05:00Z',
    },
    spec: {
      source: { matchLabels: { role: 'drone' } },
      destination: { matchLabels: { role: 'ground-station' } },
      policy: {
        bandwidth: '10Mbps',
        latency: '50ms',
        jitter: '10ms',
        packetLoss: '0.5%',
      },
    },
    status: {
      phase: 'Running',
      appliedLinks: 10,
    },
  },
  {
    apiVersion: 'simulation.kuro.io/v1alpha1',
    kind: 'TrafficControl',
    metadata: {
      name: 'sensor-to-gateway',
      namespace: 'kuro-experiment',
      uid: 'tc-002',
      creationTimestamp: '2026-02-17T14:35:00Z',
    },
    spec: {
      source: { matchLabels: { role: 'client' } },
      destination: { matchLabels: { role: 'gateway' } },
      policy: {
        bandwidth: '5Mbps',
        latency: '20ms',
        jitter: '5ms',
        packetLoss: '0.1%',
      },
    },
    status: {
      phase: 'Running',
      appliedLinks: 30,
    },
  },
];

// ============================================================================
// Mock Nodes Generator
// ============================================================================

export function generateMockNodes(topology: NetworkTopology): TopologyNode[] {
  const nodes: TopologyNode[] = [];
  let nodeIndex = 0;
  
  // Simple grid layout
  const nodesPerRow = 5;
  
  topology.spec.nodeGroups.forEach((group, groupIdx) => {
    for (let i = 0; i < group.replicas; i++) {
      const row = Math.floor(nodeIndex / nodesPerRow);
      const col = nodeIndex % nodesPerRow;
      
      const role = (group.labels?.role as NodeRole) || 'custom';
      
      nodes.push({
        id: `node-${topology.metadata.uid}-${nodeIndex}`,
        name: `${group.name}-${i}`,
        role,
        ip: randomIp(),
        labels: group.labels || {},
        status: Math.random() > 0.1 ? 'running' : 'pending',
        groupId: group.name,
        x: 100 + col * 180,
        y: 100 + row * 150 + groupIdx * 50,
      });
      
      nodeIndex++;
    }
  });
  
  return nodes;
}

// ============================================================================
// Mock Links Generator
// ============================================================================

export function generateMockLinks(nodes: TopologyNode[], tcs: TrafficControl[]): TopologyLink[] {
  const links: TopologyLink[] = [];
  const linkMap = new Map<string, boolean>();
  
  // Helper to check if nodes match selector
  const matchesSelector = (node: TopologyNode, selector: { matchLabels: Record<string, string> }): boolean => {
    return Object.entries(selector.matchLabels).every(
      ([key, value]) => node.labels[key] === value
    );
  };
  
  // Generate links based on TrafficControls
  tcs.forEach((tc) => {
    const sourceNodes = nodes.filter((n) => matchesSelector(n, tc.spec.source));
    const destNodes = nodes.filter((n) => matchesSelector(n, tc.spec.destination));
    
    sourceNodes.forEach((src) => {
      destNodes.forEach((dst) => {
        if (src.id === dst.id) return;
        
        // Avoid duplicate links
        const linkKey = [src.id, dst.id].sort().join('-');
        if (linkMap.has(linkKey)) return;
        linkMap.set(linkKey, true);
        
        links.push({
          id: `link-${src.id}-${dst.id}`,
          sourceId: src.id,
          targetId: dst.id,
          policy: tc.spec.policy,
          status: 'active',
          metrics: generateLinkMetrics(),
        });
      });
    });
  });
  
  // If no links from TrafficControls, create some random links
  if (links.length === 0 && nodes.length > 1) {
    for (let i = 0; i < nodes.length - 1; i++) {
      if (Math.random() > 0.3) {
        links.push({
          id: `link-${nodes[i].id}-${nodes[i + 1].id}`,
          sourceId: nodes[i].id,
          targetId: nodes[i + 1].id,
          policy: {
            bandwidth: '100Mbps',
            latency: '10ms',
            jitter: '2ms',
            packetLoss: '0.01%',
          },
          status: 'active',
          metrics: generateLinkMetrics(),
        });
      }
    }
  }
  
  return links;
}

// ============================================================================
// Mock Metrics Generator
// ============================================================================

export function generateLinkMetrics(): LinkMetrics {
  return {
    bandwidthUsage: randomFloat(10, 80),
    currentLatency: randomFloat(5, 100),
    currentJitter: randomFloat(1, 20),
    packetLossRate: randomFloat(0, 2),
    bytesPerSecond: randomInt(100000, 10000000),
    packetsPerSecond: randomInt(100, 10000),
  };
}

export function generateNodeMetrics(nodeId: string): NodeMetrics {
  return {
    nodeId,
    cpuUsage: generateTimeSeries(60, 30, 20),
    memoryUsage: generateTimeSeries(60, 50, 15),
    networkIn: generateTimeSeries(60, 5000000, 2000000),
    networkOut: generateTimeSeries(60, 3000000, 1500000),
  };
}

export function generateLinkMetricsHistory(linkId: string): LinkMetricsHistory {
  return {
    linkId,
    bandwidth: generateTimeSeries(60, 50, 30, 60000),
    latency: generateTimeSeries(60, 30, 15, 60000),
    packetLoss: generateTimeSeries(60, 0.5, 0.5, 60000),
  };
}

// ============================================================================
// Mock Data for Specific Topology
// ============================================================================

export function getMockDataForTopology(topologyName: string) {
  const topology = mockTopologies.find((t) => t.metadata.name === topologyName);
  if (!topology) return null;
  
  const nodes = generateMockNodes(topology);
  const links = generateMockLinks(nodes, mockTrafficControls);
  
  return { topology, nodes, links };
}

// ============================================================================
// TSN Mock Data
// ============================================================================

import type { TSNSchedule, TimeSyncStatus, TSNConfig } from '../types/api';

export const mockTsnConfig: TSNConfig = {
  enabled: true,
  cycleTime: 100000, // 100ms in microseconds
  syncInterval: 125, // PTP default sync interval in ms
};

export function generateMockTsnSchedule(links: TopologyLink[]): TSNSchedule {
  const cycleTime = 100000; // 100ms
  const slots = links.slice(0, 6).map((link, index) => {
    const duration = Math.floor(cycleTime / 8); // Each slot gets ~12.5ms
    const startTime = index * duration;
    const trafficClasses: Array<'ST' | 'BE' | 'AVB'> = ['ST', 'ST', 'AVB', 'AVB', 'BE', 'BE'];
    const colors = ['#e94560', '#e94560', '#00d9ff', '#00d9ff', '#00ff88', '#00ff88'];

    return {
      id: `slot-${index}`,
      startTime,
      duration,
      trafficClass: trafficClasses[index % trafficClasses.length],
      linkId: link.id,
      color: colors[index % colors.length],
    };
  });

  return {
    cycleTime,
    slots,
  };
}

export function generateMockTimeSyncStatuses(nodes: TopologyNode[]): TimeSyncStatus[] {
  // Pick first node as grandmaster
  const grandmasterId = nodes[0]?.id || 'gm-001';

  return nodes.map((node) => {
    const isGrandmaster = node.id === grandmasterId;
    // Grandmaster has perfect sync, others have small offsets
    const offset = isGrandmaster
      ? 0
      : randomInt(-5000, 5000); // -5μs to +5μs in nanoseconds

    return {
      nodeId: node.id,
      synced: true,
      offset,
      lastSyncTime: new Date(Date.now() - randomInt(0, 10000)).toISOString(),
      grandmasterId,
      clockClass: isGrandmaster ? 6 : 52, // 6 = Locked to GPS, 52 = Locked to PTP
    };
  });
}
