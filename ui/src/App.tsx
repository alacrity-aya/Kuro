import React, { useCallback } from 'react';
import {
  ReactFlow, Background, Controls, MiniMap, Panel,
  type Node
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { useStore } from './store';
import { Sidebar } from './components/Sidebar';
import { ToastContainer } from './components/ToastContainer';

export default function App() {
  const {
    nodes, edges,
    onNodesChange, onEdgesChange, onConnect,
    selectItem
  } = useStore();

  const onEdgeClick = useCallback((event: React.MouseEvent, edge: any) => {
    selectItem('link', edge.id);
  }, [selectItem]);

  const onNodeClick = useCallback((event: React.MouseEvent, node: Node) => {
    if (node.data && typeof node.data.componentId === 'string') {
      selectItem('component', node.data.componentId);
    }
  }, [selectItem]);

  const onPaneClick = useCallback(() => {
    selectItem(null, null);
  }, [selectItem]);

  return (

    <div className="flex h-screen w-screen ...">
      <ToastContainer />
      <div className="flex h-screen w-screen overflow-hidden bg-kuro-bg">
        <div className="flex-1 h-full relative">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={onConnect}
            onEdgeClick={onEdgeClick}
            onNodeClick={onNodeClick}
            onPaneClick={onPaneClick}
            fitView
            colorMode="dark"
          >
            <Background color="#373a40" gap={20} />
            <Controls className="bg-kuro-panel border-kuro-border fill-white" />
            <MiniMap className="bg-kuro-panel" nodeColor="#4dabf7" />

            <Panel position="top-left" className="bg-kuro-panel p-2 rounded text-xs text-gray-400 border border-kuro-border pointer-events-none">
              Nodes represent Pods.<br />
              Color border indicates same Component.
            </Panel>
          </ReactFlow>
        </div>
        <Sidebar />
      </div>
    </div>
  );
}
