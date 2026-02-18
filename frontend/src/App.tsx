import { BrowserRouter, Routes, Route, useNavigate, useLocation, useParams } from 'react-router-dom';
import { Layout } from './components/Layout';
import { Dashboard, TopologyList, TopologyDetail, TopologyCreate } from './pages';
import { useTopologyStore } from './stores';
import type { MenuItem } from './types/api';
import './App.css';

// Menu items for sidebar navigation
const menuItems: MenuItem[] = [
  { id: 'dashboard', label: 'Dashboard', icon: 'dashboard' },
  { id: 'topologies', label: 'Topologies', icon: 'topology' },
  { id: 'metrics', label: 'Metrics', icon: 'metrics' },
];

// Get active menu item from current path
function getActiveMenuItem(pathname: string): string {
  if (pathname === '/' || pathname === '/dashboard') return 'dashboard';
  if (pathname.startsWith('/topologies')) return 'topologies';
  if (pathname.startsWith('/metrics')) return 'metrics';
  return 'dashboard';
}

// Placeholder for Metrics page
function MetricsPlaceholder() {
  return (
    <div className="app-placeholder">
      <h2>Metrics</h2>
      <p>Metrics visualization coming soon...</p>
    </div>
  );
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
          <Route path="/metrics" element={<MetricsPlaceholder />} />
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

function App() {
  return (
    <BrowserRouter>
      <AppContent />
    </BrowserRouter>
  );
}

export default App;