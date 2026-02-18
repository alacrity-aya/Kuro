import Sidebar, { type MenuItem } from './Sidebar';
import './Layout.css';

interface LayoutProps {
  children: React.ReactNode;
  sidebarCollapsed?: boolean;
  onToggleSidebar?: () => void;
  menuItems?: MenuItem[];
  activeMenuItem?: string;
  onMenuItemClick?: (id: string) => void;
}

const defaultMenuItems: MenuItem[] = [
  { id: 'dashboard', label: 'Dashboard', icon: 'dashboard' },
  { id: 'topologies', label: 'Topologies', icon: 'topology' },
  { id: 'nodes', label: 'Nodes', icon: 'node' },
  { id: 'metrics', label: 'Metrics', icon: 'metrics' },
  { id: 'settings', label: 'Settings', icon: 'settings' },
];

function Layout({
  children,
  sidebarCollapsed = false,
  onToggleSidebar,
  menuItems = defaultMenuItems,
  activeMenuItem = 'dashboard',
  onMenuItemClick,
}: LayoutProps) {
  return (
    <div className="layout">
      <Sidebar
        items={menuItems}
        collapsed={sidebarCollapsed}
        activeItem={activeMenuItem}
        onItemClick={onMenuItemClick ?? (() => {})}
        onToggleCollapse={onToggleSidebar ?? (() => {})}
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
