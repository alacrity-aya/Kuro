import { BrowserRouter, Routes, Route, useNavigate, useLocation, useParams } from 'react-router-dom';
import { useState, useEffect } from 'react';
import { Layout } from './components/Layout';
import { Dashboard, TopologyList, TopologyDetail, TopologyCreate, MetricsPage } from './pages';
import { useTopologyStore } from './stores';
import { apiClient } from './api/client';
import type { MenuItem, NetworkTopology } from './types/api';
import './App.css';

// Menu items for sidebar navigation
const menuItems: MenuItem[] = [
  { id: 'dashboard', label: 'Dashboard', icon: 'dashboard' },
  { id: 'topologies', label: 'Topologies', icon: 'topology' },
  { id: 'traffic-controls', label: 'Traffic Controls', icon: 'node' },
  { id: 'metrics', label: 'Metrics', icon: 'metrics' },
];

// Get active menu item from current path
function getActiveMenuItem(pathname: string): string {
  if (pathname === '/' || pathname === '/dashboard') return 'dashboard';
  if (pathname.startsWith('/topologies')) return 'topologies';
  if (pathname.startsWith('/traffic-controls')) return 'traffic-controls';
  if (pathname.startsWith('/metrics')) return 'metrics';
  return 'dashboard';
}

// Main app content with router hooks
function AppContent() {
  const navigate = useNavigate();
  const location = useLocation();
  
  // Get sidebar state from store
  const sidebarCollapsed = useTopologyStore((state) => state.sidebarCollapsed);
  const setSidebarCollapsed = useTopologyStore((state) => state.setSidebarCollapsed);

  const activeMenuItem = getActiveMenuItem(location.pathname);

  const handleMenuItemClick = (id: string) => {
    switch (id) {
      case 'dashboard':
        navigate('/');
        break;
      case 'topologies':
        navigate('/topologies');
        break;
      case 'traffic-controls':
        navigate('/traffic-controls');
        break;
      case 'metrics':
        navigate('/metrics');
        break;
      default:
        navigate('/');
    }
  };

  // Navigate to topology detail page
  const handleViewTopology = (name: string, namespace: string = 'default') => {
    navigate(`/topologies/${namespace}/${name}`);
  };

  // Navigate to create topology page
  const handleCreateTopology = () => {
    navigate('/topologies/create');
  };

  // Handle topology created
  const handleTopologyCreated = (name: string, namespace: string = 'default') => {
    navigate(`/topologies/${namespace}/${name}`);
  };

  return (
    <Layout
      sidebarCollapsed={sidebarCollapsed}
      onToggleSidebar={() => setSidebarCollapsed(!sidebarCollapsed)}
      menuItems={menuItems}
      activeMenuItem={activeMenuItem}
      onMenuItemClick={handleMenuItemClick}
    >
      <div className="app-container">
        <Routes>
          <Route path="/" element={<Dashboard onViewTopology={handleViewTopology} onCreateTopology={handleCreateTopology} />} />
          <Route path="/dashboard" element={<Dashboard onViewTopology={handleViewTopology} onCreateTopology={handleCreateTopology} />} />
          <Route path="/topologies" element={<TopologyList onViewTopology={handleViewTopology} onCreateTopology={handleCreateTopology} />} />
          <Route 
            path="/topologies/create" 
            element={
              <TopologyCreate 
                onCreated={handleTopologyCreated}
                onCancel={() => navigate('/topologies')} 
              />
            } 
          />
          <Route 
            path="/topologies/:namespace/:name" 
            element={<TopologyDetailWrapper onBack={() => navigate('/topologies')} />} 
          />
          <Route 
            path="/topologies/:namespace/:name/edit" 
            element={
              <TopologyEditWrapper 
                onSaved={(name, namespace) => navigate(`/topologies/${namespace}/${name}`)} 
                onCancel={() => navigate('/topologies')} 
              />
            } 
          />
          <Route path="/metrics" element={<MetricsPage />} />
          <Route path="*" element={<Dashboard onViewTopology={handleViewTopology} onCreateTopology={handleCreateTopology} />} />
        </Routes>
      </div>
    </Layout>
  );
}

// Wrapper for TopologyDetail to extract route params
function TopologyDetailWrapper({ onBack }: { onBack: () => void }) {
  const { namespace = 'default', name = '' } = useParams<{ namespace: string; name: string }>();

  return (
    <TopologyDetail
      topologyName={name}
      namespace={namespace}
      onBack={onBack}
    />
  );
}

// Wrapper for TopologyCreate in edit mode
function TopologyEditWrapper({ onSaved, onCancel }: { onSaved: (name: string, namespace: string) => void; onCancel: () => void }) {
  const { namespace = 'kuro-experiment', name = '' } = useParams<{ namespace: string; name: string }>();
  const [topology, setTopology] = useState<NetworkTopology | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadTopology() {
      try {
        const response = await apiClient.getTopology(name, namespace);
        if (response.success && response.data) {
          setTopology(response.data);
        } else {
          setError(response.error || 'Failed to load topology');
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load topology');
      } finally {
        setLoading(false);
      }
    }
    
    if (name && namespace) {
      loadTopology();
    }
  }, [name, namespace]);

  if (loading) {
    return (
      <div className="topology-create">
        <div className="topology-create__loading">
          <div className="topology-create__spinner" />
          <span>Loading topology...</span>
        </div>
      </div>
    );
  }

  if (error || !topology) {
    return (
      <div className="topology-create">
        <div className="topology-create__error">
          <span className="topology-create__error-icon">⚠️</span>
          <span>{error || 'Topology not found'}</span>
          <button className="btn btn--secondary" onClick={onCancel}>
            ← Back
          </button>
        </div>
      </div>
    );
  }

  return (
    <TopologyCreate
      isEdit={true}
      initialTopology={topology}
      onCreated={onSaved}
      onCancel={onCancel}
    />
  );
}

function App() {
  return (
    <BrowserRouter>
      <AppContent />
    </BrowserRouter>
  );
}

export default App;