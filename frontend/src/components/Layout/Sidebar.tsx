import './Sidebar.css';

export interface MenuItem {
  id: string;
  label: string;
  icon: 'dashboard' | 'topology' | 'node' | 'grafana' | 'settings';
}

interface SidebarProps {
  items: MenuItem[];
  collapsed: boolean;
  activeItem: string;
  onItemClick: (id: string) => void;
  onToggleCollapse: () => void;
}

const iconMap: Record<MenuItem['icon'], string> = {
  dashboard: '📊',
  topology: '🔗',
  node: '📦',
  grafana: '📈',
  settings: '⚙️',
};

function Sidebar({ items, collapsed, activeItem, onItemClick, onToggleCollapse }: SidebarProps) {
  return (
    <aside className={`sidebar ${collapsed ? 'sidebar--collapsed' : ''}`}>
      <div className="sidebar__header">
        <div className="sidebar__logo">
          <span className="sidebar__logo-icon">🌐</span>
          {!collapsed && <span className="sidebar__logo-text">Kuro</span>}
        </div>
        <button
          className="sidebar__toggle"
          onClick={onToggleCollapse}
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed ? '→' : '←'}
        </button>
      </div>

      <nav className="sidebar__nav">
        <ul className="sidebar__menu">
          {items.map((item) => (
            <li key={item.id}>
              <button
                className={`sidebar__item ${activeItem === item.id ? 'sidebar__item--active' : ''}`}
                onClick={() => onItemClick(item.id)}
                title={collapsed ? item.label : undefined}
              >
                <span className="sidebar__item-icon">{iconMap[item.icon]}</span>
                {!collapsed && <span className="sidebar__item-label">{item.label}</span>}
              </button>
            </li>
          ))}
        </ul>
      </nav>

      <div className="sidebar__footer">
        {!collapsed && (
          <div className="sidebar__version">
            <span>v0.1.0</span>
          </div>
        )}
      </div>
    </aside>
  );
}

export default Sidebar;
