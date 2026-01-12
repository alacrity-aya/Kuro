// src/types.ts

export interface Resources {
    limits?: { cpu: string; memory: string };
    requests?: { cpu: string; memory: string };
}
export interface ToastMessage {
    id: string;
    title: string;
    type: 'success' | 'error' | 'info';
}

export interface Component {
    id: string;
    name: string;
    replicas: number;
    image: string;
    command?: string[];
    args?: string[];
    env?: Record<string, string>;
    resources?: Resources;
}

export type ShapingType = 'tbf' | 'policing' | 'htb';
export type SelectorMode = 'topology_aware' | 'manual';

export interface Selector {
    mode: SelectorMode;
    protocol?: 'TCP' | 'UDP' | 'ICMP' | 'ALL';
    dest_port?: number;
}

export interface QoS {
    bandwidth: string;
    burst?: string;
    latency?: string;
    jitter?: string;
    loss?: string;
    shaping_type?: ShapingType;
}

export interface Link {
    id: string;
    source: string;
    target: string;
    selector: Selector;
    qos: QoS;
}

export interface GlobalDefaults {
    namespace: string;
    physical_capacity: string;
    background_rate: string;
    background_burst: string;
}
