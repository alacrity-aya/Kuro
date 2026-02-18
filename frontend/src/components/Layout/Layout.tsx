import { useState } from 'react';
import Sidebar, { type MenuItem } from './Sidebar';
import './Layout.css';

interface LayoutProps {
  children: React.ReactNode;
  menuItems?: MenuItem[];
  activeItem?: string;
  onItemClick?: (id: string) => void;
}

const defaultMenuItems: MenuItem[] = [
  { id: 'dashboard', label: 'Dashboard', icon: 'dashboard' },
  { id: 'topologies', label: 'Topologies', icon: 'topology' },
  { id: 'nodes', label: 'Nodes', icon: 'node' },
  { id: 'metrics', label: 'Metrics', icon: 'metrics' },
  { id: 'settings', label: 'Settings', icon: 'settings' },
];

function Layout({ children, menuItems = defaultMenuItems, activeItem, onItemClick }: LayoutProps) {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [internalActiveItem, setInternalActiveItem] = useState('dashboard');

  const currentActiveItem = activeItem ?? internalActiveItem;

  const handleItemClick = (id: string) => {
    if (onItemClick) {
      onItemClick(id);
    } else {
      setInternalActiveItem(id);
    }
  };

  return (
    <div className="layout">
      <Sidebar
        items={menuItems}
        collapsed={sidebarCollapsed}
        activeItem={currentActiveItem}
        onItemClick={handleItemClick}
        onToggleCollapse={() => setSidebarCollapsed(!sidebarCollapsed)}
      />
      <main className="layout-main">
        <div className="layout-content">
          {children}
        </div>
      </main>
    </div>
  );
}

export default Layout;
