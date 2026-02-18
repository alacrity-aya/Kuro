import { useState, useEffect } from 'react';
import { Layout } from './components/Layout';
import { TopologyCanvas } from './components/topology';
import { apiClient } from './api/client';
import type { TopologyNode, TopologyLink } from './types/api';
import './App.css';

function App() {
  const [nodes, setNodes] = useState<TopologyNode[]>([]);
  const [links, setLinks] = useState<TopologyLink[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | undefined>();

  useEffect(() => {
    async function loadTopology() {
      try {
        setLoading(true);
        // Load the first topology for demo
        const topologyName = 'drone-swarm-demo';
        const [nodesRes, linksRes] = await Promise.all([
          apiClient.getTopologyNodes(topologyName),
          apiClient.getTopologyLinks(topologyName),
        ]);

        if (nodesRes.success && nodesRes.data) {
          setNodes(nodesRes.data);
        }
        if (linksRes.success && linksRes.data) {
          setLinks(linksRes.data);
        }
      } catch (err) {
        setError('Failed to load topology');
        console.error(err);
      } finally {
        setLoading(false);
      }
    }

    loadTopology();
  }, []);

  const handleNodeClick = (node: TopologyNode) => {
    setSelectedNodeId(node.id === selectedNodeId ? undefined : node.id);
    console.log('Node clicked:', node);
  };

  const handleEdgeClick = (link: TopologyLink) => {
    console.log('Edge clicked:', link);
  };

  return (
    <Layout>
      <div className="app-container">
        {loading && (
          <div className="app-loading">
            <div className="app-loading__spinner" />
            <span>Loading topology...</span>
          </div>
        )}
        {error && (
          <div className="app-error">
            <span>⚠️ {error}</span>
          </div>
        )}
        {!loading && !error && (
          <div className="app-topology">
            <div className="app-topology__header">
              <h2>Drone Swarm Demo</h2>
              <span className="app-topology__stats">
                {nodes.length} nodes · {links.length} links
              </span>
            </div>
            <div className="app-topology__canvas">
              <TopologyCanvas
                nodes={nodes}
                links={links}
                selectedNodeId={selectedNodeId}
                onNodeClick={handleNodeClick}
                onEdgeClick={handleEdgeClick}
                fitView
              />
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
}

export default App;
