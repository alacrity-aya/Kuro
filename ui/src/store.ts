import { create } from 'zustand';
import * as types from './types';
import * as react from '@xyflow/react';
import dagre from 'dagre';
import type { ToastMessage } from './types';

const COMPONENT_COLORS = [
    '#228be6', '#12b886', '#7950f2', '#fa5252', '#fd7e14', '#82c91e', '#be4bdb',
];

interface KuroState {
    defaults: types.GlobalDefaults;
    components: types.Component[];
    links: types.Link[];

    nodes: react.Node[];
    edges: react.Edge[];
    selectedComponentId: string | null;
    selectedLinkId: string | null;

    jsonErrors: Record<string, boolean>;
    setJsonError: (key: string, hasError: boolean) => void;

    updateDefaults: (defaults: Partial<types.GlobalDefaults>) => void;
    addComponent: (component: Omit<types.Component, 'id'>) => void;
    updateComponent: (id: string, updates: Partial<types.Component>) => void;
    removeComponent: (id: string) => void;

    onNodesChange: (changes: react.NodeChange[]) => void;
    onEdgesChange: (changes: react.EdgeChange[]) => void;
    onConnect: (connection: react.Connection) => void;

    updateLinkQoS: (id: string, qos: Partial<types.QoS>) => void;
    updateLinkSelector: (id: string, selector: Partial<types.Selector>) => void;
    selectItem: (type: 'component' | 'link' | null, id: string | null) => void;

    syncVisuals: () => void;
    layoutNodes: () => void;

    toasts: ToastMessage[];
    addToast: (title: string, type?: 'success' | 'error' | 'info') => void;
    removeToast: (id: string) => void;
}

const DEFAULT_QOS: types.QoS = { bandwidth: '10Mbps', latency: '0ms', loss: '0%', shaping_type: 'tbf' };
const DEFAULT_SELECTOR: types.Selector = { mode: 'topology_aware' };

export const useStore = create<KuroState>((set, get) => ({
    defaults: {
        namespace: 'kuro-experiment-a',
        physical_capacity: '1Gbps',
        background_rate: '900Mbps',
        background_burst: '100KB'
    },
    components: [],
    links: [],
    nodes: [],
    edges: [],
    jsonErrors: {},
    selectedComponentId: null,
    selectedLinkId: null,

    updateDefaults: (defs) => set((state) => ({ defaults: { ...state.defaults, ...defs } })),

    addComponent: (comp) => {
        const newComp = { ...comp, id: crypto.randomUUID() };
        set((state) => ({ components: [...state.components, newComp] }));
        get().syncVisuals();
    },

    updateComponent: (id, updates) => {
        set((state) => ({
            components: state.components.map(c => c.id === id ? { ...c, ...updates } : c)
        }));
        get().syncVisuals();
    },

    setJsonError: (key, hasError) => set(state => {
        const newErrors = { ...state.jsonErrors };
        if (hasError) {
            newErrors[key] = true;
        } else {
            delete newErrors[key];
        }
        return { jsonErrors: newErrors };
    }),

    removeComponent: (id) => {
        set((state) => {
            const newErrors = { ...state.jsonErrors };
            Object.keys(newErrors).forEach(k => {
                if (k.startsWith(id)) delete newErrors[k];
            });

            return {
                components: state.components.filter(c => c.id !== id),
                links: state.links.filter(l => {
                    const comp = state.components.find(c => c.id === id);
                    if (!comp) return false;
                    return !l.source.startsWith(comp.name) && !l.target.startsWith(comp.name);
                }),
                jsonErrors: newErrors
            };
        });
        get().syncVisuals();
    },
    onConnect: (params) => {
        const { links } = get();
        const exists = links.some(l => l.source === params.source && l.target === params.target);
        if (exists) {
            console.warn("Link already exists, skipping creation.");
            return;
        }

        const newLink: types.Link = {
            id: `link-${params.source}-${params.target}`,
            source: params.source,
            target: params.target,
            selector: { ...DEFAULT_SELECTOR },
            qos: { ...DEFAULT_QOS }
        };

        set((state) => ({
            links: [...state.links, newLink],
        }));
        get().syncVisuals();
    },

    syncVisuals: () => {
        const { components, links, nodes } = get();
        const existingPositions = new Map(nodes.map(n => [n.id, n.position]));

        const newNodes: react.Node[] = [];

        components.forEach((comp, idx) => {
            const color = COMPONENT_COLORS[idx % COMPONENT_COLORS.length];
            for (let i = 0; i < comp.replicas; i++) {
                const podName = `${comp.name}-${i}`;
                const position = existingPositions.get(podName) || { x: 50 + (idx * 250), y: 50 + (i * 80) };

                newNodes.push({
                    id: podName,
                    type: 'default',
                    position: position,
                    data: { label: podName, componentId: comp.id },
                    style: {
                        background: '#1a1b1e',
                        color: 'white',
                        border: `2px solid ${color}`,
                        borderRadius: 8,
                        width: 180,
                        padding: 10,
                        boxShadow: `0 0 10px ${color}33`
                    },
                });
            }
        });

        const newEdges: react.Edge[] = links.map(link => ({
            id: link.id,
            source: link.source,
            target: link.target,
            label: link.qos.bandwidth,
            animated: true,
            markerEnd: { type: react.MarkerType.ArrowClosed },
            style: { stroke: '#4dabf7', strokeWidth: 2 },
            type: 'default'
        }));

        set({ nodes: newNodes, edges: newEdges });
    },

    layoutNodes: () => {
        const { nodes, edges } = get();
        const dagreGraph = new dagre.graphlib.Graph();
        dagreGraph.setDefaultEdgeLabel(() => ({}));
        const nodeWidth = 200;
        const nodeHeight = 60;
        dagreGraph.setGraph({ rankdir: 'LR' });

        nodes.forEach((node) => {
            dagreGraph.setNode(node.id, { width: nodeWidth, height: nodeHeight });
        });

        edges.forEach((edge) => {
            dagreGraph.setEdge(edge.source, edge.target);
        });

        dagre.layout(dagreGraph);

        const layoutedNodes = nodes.map((node) => {
            const nodeWithPosition = dagreGraph.node(node.id);
            return {
                ...node,
                position: {
                    x: nodeWithPosition.x - nodeWidth / 2,
                    y: nodeWithPosition.y - nodeHeight / 2,
                },
            };
        });

        set({ nodes: layoutedNodes });
    },

    onNodesChange: (changes) => {
        set({ nodes: react.applyNodeChanges(changes, get().nodes) });
    },

    onEdgesChange: (changes) => {
        const { edges, links } = get();
        const newEdges = react.applyEdgeChanges(changes, edges);



        const newEdgeIds = new Set(newEdges.map(e => e.id));
        const newLinks = links.filter(l => newEdgeIds.has(l.id));

        set({ edges: newEdges, links: newLinks });
    },

    updateLinkQoS: (id, qos) => {
        set(state => {
            const newLinks = state.links.map(l => l.id === id ? { ...l, qos: { ...l.qos, ...qos } } : l);
            return { links: newLinks };
        });
        get().syncVisuals();
    },


    updateLinkSelector: (id, selectorUpdates) => {
        set(state => {
            const newLinks = state.links.map(l =>
                l.id === id ? { ...l, selector: { ...l.selector, ...selectorUpdates } } : l
            );
            return { links: newLinks };
        });

        get().syncVisuals();
    },

    selectItem: (type, id) => {
        set({ selectedComponentId: type === 'component' ? id : null, selectedLinkId: type === 'link' ? id : null });
    },

    toasts: [],
    addToast: (title, type = 'info') => {
        const id = crypto.randomUUID();
        set(state => ({ toasts: [...state.toasts, { id, title, type }] }));

        setTimeout(() => get().removeToast(id), 3000);
    },
    removeToast: (id) => {
        set(state => ({ toasts: state.toasts.filter(t => t.id !== id) }));
    }

}));
