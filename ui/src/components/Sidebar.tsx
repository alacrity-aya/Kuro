import React, { useState } from 'react';
import { useStore } from '../store';
import {
    Download, Plus, Server, Network, LayoutTemplate,
    Copy, Check, FileText, Settings, Cpu, Terminal, Shield
} from 'lucide-react';
import yaml from 'js-yaml';
import { Modal } from './Modal';

export const Sidebar = () => {
    const store = useStore();
    const selectedComponent = store.components.find(c => c.id === store.selectedComponentId);
    const selectedLink = store.links.find(l => l.id === store.selectedLinkId);

    const hasErrors = Object.keys(store.jsonErrors).length > 0;

    // === State Management ===
    const [isAddModalOpen, setIsAddModalOpen] = useState(false);
    const [newComponentName, setNewComponentName] = useState('');

    const [isExportModalOpen, setIsExportModalOpen] = useState(false);
    const [generatedYamls, setGeneratedYamls] = useState({ workload: '', topology: '' });
    const [copyStatus, setCopyStatus] = useState<'idle' | 'copied'>('idle');

    // === Actions ===
    const handleOpenAddModal = () => {
        setNewComponentName('');
        setIsAddModalOpen(true);
    };

    const handleJsonBlur = (val: string, field: 'command' | 'args', componentId: string) => {
        const errorKey = `${componentId}-${field}`;

        if (!val.trim()) {
            store.updateComponent(componentId, { [field]: undefined });
            store.setJsonError(errorKey, false);
            return;
        }

        try {
            const parsed = JSON.parse(val);
            if (!Array.isArray(parsed)) throw new Error("Must be array");
            store.updateComponent(componentId, { [field]: parsed });
            store.setJsonError(errorKey, false);
        } catch (e) {
            store.setJsonError(errorKey, true);
            store.addToast(`Invalid JSON for ${field}: Must be ["a", "b"]`, 'error');
        }
    };

    const handleConfirmAdd = () => {
        if (!newComponentName.trim()) return;
        store.addComponent({
            name: newComponentName,
            replicas: 1,
            image: 'nicolaka/netshoot:latest',
            resources: { limits: { cpu: '500m', memory: '512Mi' } }
        });
        setIsAddModalOpen(false);
    };

    const parseEnvString = (str: string) => {
        const env: Record<string, string> = {};
        str.split('\n').forEach(line => {
            const [key, ...valParts] = line.split('=');
            if (key && valParts.length > 0) env[key.trim()] = valParts.join('=').trim();
        });
        return env;
    };

    const envToString = (env?: Record<string, string>) => {
        if (!env) return '';
        return Object.entries(env).map(([k, v]) => `${k}=${v}`).join('\n');
    };

    const handleGenerate = () => {
        const cleanComponents = store.components.map(({ id, ...rest }) => {
            const comp: any = { ...rest };
            if (!comp.command || comp.command.length === 0) delete comp.command;
            if (!comp.args || comp.args.length === 0) delete comp.args;
            if (!comp.env || Object.keys(comp.env).length === 0) delete comp.env;
            return comp;
        });

        const workloadObj = {
            apiVersion: 'kuro.io/v1alpha1',
            kind: 'ExperimentWorkload',
            metadata: {
                name: `${store.defaults.namespace}-workload`,
                namespace: store.defaults.namespace
            },
            spec: {
                components: cleanComponents
            }
        };

        const topologyObj = {
            apiVersion: 'kuro.io/v1alpha1',
            kind: 'NetworkTopology',
            metadata: {
                name: `${store.defaults.namespace}-topo`,
                namespace: store.defaults.namespace
            },
            spec: {
                defaults: store.defaults,
                nodes: store.nodes.map(n => ({ name: n.id })),
                links: store.links
            }
        };

        const yamlOptions = { lineWidth: 120, noRefs: true };

        setGeneratedYamls({
            workload: yaml.dump(workloadObj, yamlOptions),
            topology: yaml.dump(topologyObj, yamlOptions)
        });
        setIsExportModalOpen(true);
    };

    const downloadFile = (content: string, filename: string) => {
        const blob = new Blob([content], { type: 'text/yaml' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    };

    const handleCopy = () => {
        const allContent = `# Workload.yaml\n${generatedYamls.workload}\n---\n# Topology.yaml\n${generatedYamls.topology}`;
        navigator.clipboard.writeText(allContent);
        setCopyStatus('copied');
        setTimeout(() => setCopyStatus('idle'), 2000);
    };

    return (
        <>
            <aside className="w-96 bg-kuro-panel border-l border-kuro-border h-full flex flex-col overflow-hidden">
                {/* Header */}
                <div className="p-4 border-b border-gray-700 bg-black/20">
                    <h2 className="text-xl font-bold text-white flex items-center gap-2">
                        <Server size={20} /> Kuro Editor
                    </h2>
                </div>

                <div className="flex-1 overflow-y-auto p-4 space-y-6">

                    {/* 1. Global Defaults */}
                    <section className="space-y-3">
                        <h3 className="text-xs font-bold text-gray-400 uppercase tracking-wider flex items-center gap-2">
                            <Settings size={12} /> Global Topology Defaults
                        </h3>
                        <div className="bg-gray-800/50 p-3 rounded border border-gray-700 grid grid-cols-2 gap-3">
                            <div className="col-span-2">
                                <label className="text-xs text-gray-500">Namespace</label>
                                <input
                                    className="w-full bg-black/30 rounded px-2 py-1 text-sm text-blue-300 border border-gray-600 focus:border-blue-500 outline-none"
                                    value={store.defaults.namespace || ''}
                                    onChange={(e) => store.updateDefaults({ namespace: e.target.value })}
                                />
                            </div>
                            <div>
                                <label className="text-xs text-gray-500">Physical Cap</label>
                                <input
                                    className="w-full bg-black/30 rounded px-2 py-1 text-xs text-white border border-gray-600 focus:border-blue-500 outline-none"
                                    placeholder="1Gbps"
                                    value={store.defaults.physical_capacity || ''}
                                    onChange={(e) => store.updateDefaults({ physical_capacity: e.target.value })}
                                />
                            </div>
                            <div>
                                <label className="text-xs text-gray-500">Bg Rate</label>
                                <input
                                    className="w-full bg-black/30 rounded px-2 py-1 text-xs text-white border border-gray-600 focus:border-blue-500 outline-none"
                                    placeholder="900Mbps"
                                    value={store.defaults.background_rate || ''}
                                    onChange={(e) => store.updateDefaults({ background_rate: e.target.value })}
                                />
                            </div>
                            <div>
                                <label className="text-xs text-gray-500">Bg Burst</label>
                                <input
                                    className="w-full bg-black/30 rounded px-2 py-1 text-xs text-white border border-gray-600 focus:border-blue-500 outline-none"
                                    placeholder="100KB"
                                    value={store.defaults.background_burst || ''}
                                    onChange={(e) => store.updateDefaults({ background_burst: e.target.value })}
                                />
                            </div>
                        </div>
                    </section>

                    <hr className="border-gray-700" />

                    {/* 2. Actions */}
                    <div className="grid grid-cols-2 gap-2">
                        <button
                            onClick={handleOpenAddModal}
                            className="flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-700 text-white py-2 rounded text-sm transition-colors"
                        >
                            <Plus size={16} /> Add Workload
                        </button>
                        <button
                            onClick={() => store.layoutNodes()}
                            className="flex items-center justify-center gap-2 bg-purple-600 hover:bg-purple-700 text-white py-2 rounded text-sm transition-colors"
                        >
                            <LayoutTemplate size={16} /> Auto Sort
                        </button>
                    </div>

                    {/* 3. Editor Area */}

                    {/* --- COMPONENT EDITOR --- */}
                    {selectedComponent && (
                        <div key={selectedComponent.id} className="animate-in slide-in-from-right-4 space-y-4">
                            <div className="flex justify-between items-center border-b border-gray-700 pb-2">
                                <span className="font-bold text-blue-400 text-sm flex items-center gap-2">
                                    <Cpu size={14} /> {selectedComponent.name}
                                </span>
                                <button
                                    onClick={() => store.removeComponent(selectedComponent.id)}
                                    className="text-red-400 hover:text-red-300 text-xs"
                                >Delete</button>
                            </div>

                            {/* Basic Info */}
                            <div className="grid grid-cols-2 gap-2">
                                <div>
                                    <label className="text-xs text-gray-500">Replicas</label>
                                    <input
                                        type="number" min={1}
                                        className="w-full bg-black/30 rounded px-2 py-1 text-sm text-white border border-gray-600"
                                        value={selectedComponent.replicas}
                                        onChange={(e) => store.updateComponent(selectedComponent.id, { replicas: parseInt(e.target.value) })}
                                    />
                                </div>
                                <div>
                                    <label className="text-xs text-gray-500">Image</label>
                                    <input
                                        className="w-full bg-black/30 rounded px-2 py-1 text-sm text-white border border-gray-600"
                                        value={selectedComponent.image || ''}
                                        onChange={(e) => store.updateComponent(selectedComponent.id, { image: e.target.value })}
                                    />
                                </div>
                            </div>

                            {/* Command & Args */}
                            <div className="space-y-2">
                                <div>
                                    <label className="text-xs text-gray-500 flex items-center gap-1"><Terminal size={10} /> Command (JSON Array)</label>
                                    <input
                                        key={`${selectedComponent.id}-command`}
                                        className="w-full bg-black/30 rounded px-2 py-1 text-xs text-green-400 font-mono border border-gray-600 placeholder-gray-600"
                                        placeholder='["sleep", "infinity"]'
                                        defaultValue={JSON.stringify(selectedComponent.command || [])}
                                        onBlur={(e) => handleJsonBlur(e.target.value, 'command', selectedComponent.id)}
                                    />
                                </div>
                                <div>
                                    <label className="text-xs text-gray-500">Args (JSON Array)</label>
                                    <input
                                        key={`${selectedComponent.id}-args`}
                                        className="w-full bg-black/30 rounded px-2 py-1 text-xs text-green-400 font-mono border border-gray-600 placeholder-gray-600"
                                        placeholder='["-v", "debug"]'
                                        defaultValue={JSON.stringify(selectedComponent.args || [])}
                                        onBlur={(e) => handleJsonBlur(e.target.value, 'args', selectedComponent.id)}
                                    />
                                </div>
                            </div>

                            {/* Env Vars */}
                            <div>
                                <label className="text-xs text-gray-500 mb-1 block">Environment Variables (KEY=VALUE)</label>
                                <textarea
                                    className="w-full h-20 bg-black/30 rounded p-2 text-xs font-mono text-yellow-100 border border-gray-600 focus:border-blue-500 outline-none resize-none"
                                    placeholder="LEADER_ADDR=drone-0.drone&#10;LOG_LEVEL=debug"
                                    defaultValue={envToString(selectedComponent.env)}
                                    onBlur={(e) => store.updateComponent(selectedComponent.id, { env: parseEnvString(e.target.value) })}
                                />
                            </div>

                            {/* Resources */}
                            <div className="bg-black/20 p-2 rounded border border-gray-700/50">
                                <label className="text-xs text-gray-400 block mb-2 font-bold">Resources (Limits)</label>
                                <div className="grid grid-cols-2 gap-2">
                                    <div>
                                        <label className="text-[10px] text-gray-500">CPU</label>
                                        <input
                                            className="w-full bg-black/30 rounded px-1 py-1 text-xs text-white border border-gray-600"
                                            placeholder="500m"
                                            value={selectedComponent.resources?.limits?.cpu || ''}
                                            onChange={(e) => store.updateComponent(selectedComponent.id, {
                                                resources: { ...selectedComponent.resources, limits: { ...selectedComponent.resources?.limits, cpu: e.target.value } as any }
                                            })}
                                        />
                                    </div>
                                    <div>
                                        <label className="text-[10px] text-gray-500">Memory</label>
                                        <input
                                            className="w-full bg-black/30 rounded px-1 py-1 text-xs text-white border border-gray-600"
                                            placeholder="512Mi"
                                            value={selectedComponent.resources?.limits?.memory || ''}
                                            onChange={(e) => store.updateComponent(selectedComponent.id, {
                                                resources: { ...selectedComponent.resources, limits: { ...selectedComponent.resources?.limits, memory: e.target.value } as any }
                                            })}
                                        />
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* --- LINK QoS EDITOR --- */}
                    {selectedLink && (
                        <div key={selectedLink.id} className="animate-in slide-in-from-right-4 space-y-4 border-t border-blue-500/30 pt-4 mt-4">
                            <div className="flex justify-between items-center">
                                <span className="font-bold text-blue-400 text-sm flex items-center gap-2">
                                    <Network size={14} /> Link Config
                                </span>
                                <div className="flex gap-2">
                                    <span className="text-[10px] text-gray-500 self-center">
                                        {selectedLink.source} → {selectedLink.target}
                                    </span>
                                </div>
                            </div>

                            {/* Selector Config */}
                            <div className="bg-black/20 p-2 rounded border border-gray-700/50 space-y-2">
                                <label className="text-xs font-bold text-gray-400 block flex items-center gap-1"><Shield size={10} /> Traffic Selector</label>

                                <select
                                    className="w-full bg-black/30 rounded px-2 py-1 text-xs text-white border border-gray-600 outline-none"
                                    value={selectedLink.selector.mode || 'topology_aware'}
                                    onChange={(e) => {
                                        const mode = e.target.value as any;
                                        store.updateLinkSelector(selectedLink.id, { mode });
                                    }}
                                >
                                    <option value="topology_aware">Topology Aware (Automatic)</option>
                                    <option value="manual">Manual (Port/Protocol)</option>
                                </select>

                                {selectedLink.selector.mode === 'manual' && (
                                    <div className="grid grid-cols-2 gap-2 animate-in fade-in">
                                        <div>
                                            <label className="text-[10px] text-gray-500">Protocol</label>
                                            <select
                                                className="w-full bg-black/30 rounded px-1 py-1 text-xs text-white border border-gray-600"
                                                value={selectedLink.selector.protocol || 'UDP'}
                                                onChange={(e) => store.updateLinkSelector(selectedLink.id, { protocol: e.target.value as any })}
                                            >
                                                <option value="UDP">UDP</option>
                                                <option value="TCP">TCP</option>
                                                <option value="ICMP">ICMP</option>
                                                <option value="ALL">ALL</option>
                                            </select>
                                        </div>
                                        <div>
                                            <label className="text-[10px] text-gray-500">Dest Port</label>
                                            <input
                                                type="number"
                                                className="w-full bg-black/30 rounded px-1 py-1 text-xs text-white border border-gray-600"
                                                placeholder="8080"
                                                value={selectedLink.selector.dest_port || ''}
                                                onChange={(e) => store.updateLinkSelector(selectedLink.id, { dest_port: parseInt(e.target.value) })}
                                            />
                                        </div>
                                    </div>
                                )}
                            </div>

                            {/* QoS Config */}
                            <div className="grid grid-cols-2 gap-2">
                                <div className="col-span-2">
                                    <label className="text-xs text-gray-500">Shaping Algo</label>
                                    <select
                                        className="w-full bg-black/30 rounded px-2 py-1 text-xs text-white border border-gray-600 outline-none"
                                        value={selectedLink.qos.shaping_type || 'tbf'}
                                        onChange={(e) => store.updateLinkQoS(selectedLink.id, { shaping_type: e.target.value as any })}
                                    >
                                        <option value="tbf">TBF (Token Bucket)</option>
                                        <option value="htb">HTB (Hierarchical)</option>
                                        <option value="policing">Policing (Hard Drop)</option>
                                    </select>
                                </div>
                                <div>
                                    <label className="text-xs text-gray-500">Bandwidth</label>
                                    <input
                                        className="w-full bg-black/30 rounded px-2 py-1 text-xs text-white border border-gray-600"
                                        value={selectedLink.qos.bandwidth || ''}
                                        onChange={(e) => store.updateLinkQoS(selectedLink.id, { bandwidth: e.target.value })}
                                    />
                                </div>
                                <div>
                                    <label className="text-xs text-gray-500">Burst</label>
                                    <input
                                        className="w-full bg-black/30 rounded px-2 py-1 text-xs text-white border border-gray-600"
                                        placeholder="100KB"
                                        value={selectedLink.qos.burst || ''}
                                        onChange={(e) => store.updateLinkQoS(selectedLink.id, { burst: e.target.value })}
                                    />
                                </div>
                                <div>
                                    <label className="text-xs text-gray-500">Latency</label>
                                    <input
                                        className="w-full bg-black/30 rounded px-2 py-1 text-xs text-white border border-gray-600"
                                        value={selectedLink.qos.latency || ''}
                                        onChange={(e) => store.updateLinkQoS(selectedLink.id, { latency: e.target.value })}
                                    />
                                </div>
                                <div>
                                    <label className="text-xs text-gray-500">Jitter</label>
                                    <input
                                        className="w-full bg-black/30 rounded px-2 py-1 text-xs text-white border border-gray-600"
                                        placeholder="0ms"
                                        value={selectedLink.qos.jitter || ''}
                                        onChange={(e) => store.updateLinkQoS(selectedLink.id, { jitter: e.target.value })}
                                    />
                                </div>
                                <div>
                                    <label className="text-xs text-gray-500">Loss</label>
                                    <input
                                        className="w-full bg-black/30 rounded px-2 py-1 text-xs text-white border border-gray-600"
                                        value={selectedLink.qos.loss || ''}
                                        onChange={(e) => store.updateLinkQoS(selectedLink.id, { loss: e.target.value })}
                                    />
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Hint */}
                    {!selectedComponent && !selectedLink && (
                        <div className="text-center text-gray-600 text-xs py-10">
                            Select a Node or Link to edit details.
                        </div>
                    )}

                </div>

                {/* Footer Actions */}
                <div className="p-4 border-t border-gray-700 bg-black/20">
                    <button
                        onClick={handleGenerate}
                        disabled={hasErrors}
                        className={`w-full flex items-center justify-center gap-2 py-3 rounded font-bold shadow-lg transition-all ${hasErrors
                            ? "bg-gray-700 text-gray-500 cursor-not-allowed"
                            : "bg-green-600 hover:bg-green-700 text-white shadow-green-900/20"
                            }`}
                    >
                        <Download size={18} /> Export YAMLs
                    </button>
                </div>
            </aside>

            {/* === MODALS === */}
            <Modal
                isOpen={isAddModalOpen}
                onClose={() => setIsAddModalOpen(false)}
                title="Create New Component"
                footer={
                    <>
                        <button onClick={() => setIsAddModalOpen(false)} className="px-4 py-2 text-sm text-gray-300 hover:text-white">Cancel</button>
                        <button onClick={handleConfirmAdd} className="px-4 py-2 text-sm bg-blue-600 hover:bg-blue-500 text-white rounded">Create</button>
                    </>
                }
            >
                <div className="space-y-4">
                    <div>
                        <label className="block text-sm text-gray-400 mb-1">Component Name</label>
                        <input
                            autoFocus
                            type="text"
                            placeholder="e.g. drone-leader"
                            className="w-full bg-black/30 border border-gray-600 rounded p-2 text-white focus:border-blue-500 focus:outline-none"
                            value={newComponentName}
                            onChange={(e) => setNewComponentName(e.target.value)}
                            onKeyDown={(e) => e.key === 'Enter' && handleConfirmAdd()}
                        />
                    </div>
                </div>
            </Modal>

            <Modal
                isOpen={isExportModalOpen}
                onClose={() => setIsExportModalOpen(false)}
                title="Export Configurations"
                maxWidth="max-w-4xl"
                footer={
                    <div className="flex justify-between w-full">
                        <button
                            onClick={handleCopy}
                            className="flex items-center gap-2 px-4 py-2 text-sm bg-gray-700 hover:bg-gray-600 text-white rounded"
                        >
                            {copyStatus === 'copied' ? <Check size={16} /> : <Copy size={16} />}
                            {copyStatus === 'copied' ? 'Copied!' : 'Copy All'}
                        </button>

                        <div className="flex gap-2">
                            <button
                                onClick={() => downloadFile(generatedYamls.workload, '01-workload.yaml')}
                                className="flex items-center gap-2 px-4 py-2 text-sm bg-blue-600 hover:bg-blue-500 text-white rounded"
                            >
                                <Download size={16} /> Workload (.yaml)
                            </button>
                            <button
                                onClick={() => downloadFile(generatedYamls.topology, '02-topology.yaml')}
                                className="flex items-center gap-2 px-4 py-2 text-sm bg-green-600 hover:bg-green-500 text-white rounded"
                            >
                                <Download size={16} /> Topology (.yaml)
                            </button>
                        </div>
                    </div>
                }
            >
                <div className="grid grid-cols-2 gap-4 h-[60vh]">
                    <div className="flex flex-col h-full">
                        <div className="flex items-center gap-2 text-sm text-gray-400 mb-2">
                            <FileText size={14} /> 01-workload.yaml
                        </div>
                        <textarea
                            readOnly
                            className="flex-1 w-full bg-black/50 border border-gray-700 rounded p-3 text-xs font-mono text-green-400 focus:outline-none resize-none"
                            value={generatedYamls.workload}
                        />
                    </div>
                    <div className="flex flex-col h-full">
                        <div className="flex items-center gap-2 text-sm text-gray-400 mb-2">
                            <FileText size={14} /> 02-topology.yaml
                        </div>
                        <textarea
                            readOnly
                            className="flex-1 w-full bg-black/50 border border-gray-700 rounded p-3 text-xs font-mono text-blue-400 focus:outline-none resize-none"
                            value={generatedYamls.topology}
                        />
                    </div>
                </div>
            </Modal>
        </>
    );
};
