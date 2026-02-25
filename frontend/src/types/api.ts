// Kuro API Types
// Based on CRD definitions: NetworkTopology, TrafficControl

// ============================================================================
// Common Types
// ============================================================================

export type Phase = 'Pending' | 'Running' | 'Succeeded' | 'Failed' | 'Unknown';

// Sidebar Menu Item
export type MenuItemIcon = 'dashboard' | 'topology' | 'node' | 'metrics' | 'settings';

export interface MenuItem {
  id: string;
  label: string;
  icon: MenuItemIcon;
}

export interface ObjectMeta {
  name: string;
  namespace: string;
  uid: string;
  creationTimestamp: string;
  labels?: Record<string, string>;
  annotations?: Record<string, string>;
}

// ============================================================================
// NetworkTopology CRD Types
// ============================================================================

// UserProgram defines the code logic injected by the user
export interface UserProgram {
  source?: string;     // Source is the specific content of the code
  mountPath?: string;  // MountPath is the absolute path where the code is mounted
  filename?: string;   // Filename is the name of the mounted file, e.g., "algo.py"
}

export interface NodeGroup {
  name: string;
  replicas: number;
  image: string;
  command?: string[];           // Container startup command, e.g., ["sleep", "infinite"]
  labels?: Record<string, string>;
  resources?: {
    cpu?: string;
    memory?: string;
  };
  userProgram?: UserProgram;    // TODO: Support user code injection in UI
}

export interface NetworkTopologySpec {
  nodeGroups: NodeGroup[];
}

export interface NetworkTopologyStatus {
  phase: Phase;
  nodeCount: number;
  readyNodes: number;
  conditions?: {
    type: string;
    status: 'True' | 'False' | 'Unknown';
    message?: string;
    lastTransitionTime?: string;
  }[];
}

export interface NetworkTopology {
  apiVersion: 'simulation.kuro.io/v1alpha1';
  kind: 'NetworkTopology';
  metadata: ObjectMeta;
  spec: NetworkTopologySpec;
  status?: NetworkTopologyStatus;
}

// ============================================================================
// TrafficControl CRD Types
// ============================================================================

export interface LabelSelector {
  matchLabels: Record<string, string>;
}

export interface TrafficPolicy {
  bandwidth: string;    // e.g., "10Mbps"
  latency: string;      // e.g., "50ms"
  jitter: string;       // e.g., "10ms"
  packetLoss: string;   // e.g., "0.5%"
}

export interface TrafficControlSpec {
  source: LabelSelector;
  destination: LabelSelector;
  policy: TrafficPolicy;
}

export interface TrafficControlStatus {
  phase: Phase;
  appliedLinks: number;
  conditions?: {
    type: string;
    status: 'True' | 'False' | 'Unknown';
    message?: string;
  }[];
}

export interface TrafficControl {
  apiVersion: 'simulation.kuro.io/v1alpha1';
  kind: 'TrafficControl';
  metadata: ObjectMeta;
  spec: TrafficControlSpec;
  status?: TrafficControlStatus;
}

// ============================================================================
// Node & Link Types (for topology visualization)
// ============================================================================

export type NodeRole = 'drone' | 'ground-station' | 'gateway' | 'server' | 'client' | 'custom';

export interface TopologyNode {
  id: string;
  name: string;
  role: NodeRole;
  ip: string;
  labels: Record<string, string>;
  status: 'running' | 'pending' | 'failed' | 'unknown';
  groupId: string;
  x?: number;
  y?: number;
}

export interface TopologyLink {
  id: string;
  sourceId: string;
  targetId: string;
  policy?: TrafficPolicy;
  status: 'active' | 'inactive' | 'pending';
  metrics?: LinkMetrics;
}

export interface LinkMetrics {
  bandwidthUsage: number;    // percentage (0-100)
  currentLatency: number;    // ms
  currentJitter: number;     // ms
  packetLossRate: number;    // percentage (0-100)
  bytesPerSecond: number;
  packetsPerSecond: number;
}

// ============================================================================
// Metrics Types
// ============================================================================

export interface TimeSeriesPoint {
  timestamp: number;
  value: number;
}

export interface NodeMetrics {
  nodeId: string;
  cpuUsage: TimeSeriesPoint[];
  memoryUsage: TimeSeriesPoint[];
  networkIn: TimeSeriesPoint[];
  networkOut: TimeSeriesPoint[];
}

export interface LinkMetricsHistory {
  linkId: string;
  bandwidth: TimeSeriesPoint[];
  latency: TimeSeriesPoint[];
  packetLoss: TimeSeriesPoint[];
}

/**
 * Metrics summary for dashboard overview
 * TODO: Requires backend API - GET /api/v1/metrics/summary
 */
export interface MetricsSummary {
  totalNodes: number;
  runningNodes: number;
  totalLinks: number;
  activeLinks: number;
  avgBandwidthMbps: number;
  avgLatencyMs: number;
  avgPacketLoss: number;
  healthScore: number;  // 0-100
}

// ============================================================================
// API Response Types
// ============================================================================

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
}

export interface ListResult<T> {
  items: T[];
  totalCount: number;
  continueToken?: string;
}

// ============================================================================
// API Client Interface
// ============================================================================

export interface KuroApiClient {
  // Topology operations
  listTopologies(namespace?: string): Promise<ApiResponse<ListResult<NetworkTopology>>>;
  getTopology(name: string, namespace?: string): Promise<ApiResponse<NetworkTopology>>;
  createTopology(topology: NetworkTopology): Promise<ApiResponse<NetworkTopology>>;
  updateTopology(topology: NetworkTopology): Promise<ApiResponse<NetworkTopology>>;
  deleteTopology(name: string, namespace?: string): Promise<ApiResponse<void>>;
  
  // TrafficControl operations
  listTrafficControls(namespace?: string): Promise<ApiResponse<ListResult<TrafficControl>>>;
  getTrafficControl(name: string, namespace?: string): Promise<ApiResponse<TrafficControl>>;
  createTrafficControl(tc: TrafficControl): Promise<ApiResponse<TrafficControl>>;
  updateTrafficControl(tc: TrafficControl): Promise<ApiResponse<TrafficControl>>;
  deleteTrafficControl(name: string, namespace?: string): Promise<ApiResponse<void>>;
  
  // Topology visualization
  getTopologyNodes(topologyName: string, namespace?: string): Promise<ApiResponse<TopologyNode[]>>;
  getTopologyLinks(topologyName: string, namespace?: string): Promise<ApiResponse<TopologyLink[]>>;
  
  // Metrics
  getNodeMetrics(nodeId: string): Promise<ApiResponse<NodeMetrics>>;
  getLinkMetrics(linkId: string): Promise<ApiResponse<LinkMetricsHistory>>;
}

// ============================================================================
// TSN (Time-Sensitive Networking) Types
// ============================================================================

export interface TSNSchedule {
  cycleTime: number;        // in microseconds
  slots: TSNSlot[];
}

export interface TSNSlot {
  id: string;
  startTime: number;        // in microseconds from cycle start
  duration: number;         // in microseconds
  trafficClass: 'ST' | 'BE' | 'AVB';  // Scheduled Traffic, Best Effort, Audio Video Bridging
  linkId: string;
  color: string;
}

export interface TimeSyncStatus {
  nodeId: string;
  synced: boolean;
  offset: number;           // offset from grandmaster in nanoseconds
  lastSyncTime: string;
  grandmasterId: string;
  clockClass: number;       // PTP clock class (0-255)
}

export interface TSNConfig {
  enabled: boolean;
  cycleTime: number;        // in microseconds (default: 100000 = 100ms)
  schedule?: TSNSchedule;
  grandmasterNodeId?: string;
  syncInterval: number;     // in milliseconds
}
