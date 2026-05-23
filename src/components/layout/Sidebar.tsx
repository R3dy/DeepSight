import { NavLink, useLocation } from 'react-router-dom';
import { useState } from 'react';
import { useAuth } from '../../context/AuthContext';
import { useWebSocket } from '../../context/WebSocketContext';

interface NavItem {
  to: string;
  label: string;
  icon: string;
  badge?: string;
}

const NAV_ITEMS: NavItem[] = [
  { to: '/dashboard', label: 'Dashboard', icon: '📊' },
  { to: '/security', label: 'Security', icon: '🛡️' },
  { to: '/investigate', label: 'Investigate', icon: '🔍' },
  { to: '/admin', label: 'Admin', icon: '⚙️' },
];

function wsStatusDot(status: string): string {
  switch (status) {
    case 'connected':
      return 'bg-green-500';
    case 'connecting':
      return 'bg-amber-500 animate-pulse';
    case 'error':
      return 'bg-red-500';
    default:
      return 'bg-gray-600';
  }
}

export function Sidebar() {
  const { user, logout } = useAuth();
  const { status: wsStatus } = useWebSocket();
  const location = useLocation();
  const [collapsed, setCollapsed] = useState(false);

  return (
    <>
      {/* Mobile hamburger */}
      <button
        type="button"
        className="lg:hidden fixed top-4 left-4 z-50 p-2 rounded-lg bg-[#161b22] border border-[#30363d] text-[#e1e4e8]"
        onClick={() => setCollapsed(!collapsed)}
        aria-label={collapsed ? 'Open sidebar' : 'Close sidebar'}
      >
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          {collapsed ? (
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
          ) : (
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          )}
        </svg>
      </button>

      {/* Sidebar */}
      <aside
        className={`fixed top-0 left-0 z-40 h-screen bg-[#161b22] border-r border-[#30363d] transition-all duration-200 flex flex-col
          ${collapsed ? '-translate-x-full' : 'translate-x-0'}
          lg:translate-x-0 lg:static lg:w-56`}
      >
        {/* Logo */}
        <div className="p-4 border-b border-[#30363d]">
          <h1 className="text-lg font-bold text-[#a78bfa] tracking-tight">
            DeepSight
          </h1>
          <p className="text-xs text-[#8b949e] mt-0.5">Enterprise SIEM</p>
        </div>

        {/* Nav items */}
        <nav className="flex-1 p-2 space-y-0.5" role="navigation" aria-label="Main navigation">
          {NAV_ITEMS.map(item => {
            const isActive = location.pathname.startsWith(item.to);
            return (
              <NavLink
                key={item.to}
                to={item.to}
                className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors
                  ${isActive
                    ? 'bg-[#1c2129] text-[#a78bfa] border-l-2 border-[#a78bfa]'
                    : 'text-[#8b949e] hover:text-[#e1e4e8] hover:bg-[#1c2129] border-l-2 border-transparent'
                  }`}
                aria-current={isActive ? 'page' : undefined}
              >
                <span className="text-lg" aria-hidden="true">{item.icon}</span>
                <span>{item.label}</span>
                {item.badge && (
                  <span className="ml-auto text-xs px-1.5 py-0.5 rounded-full bg-[#f43f5e] text-white">
                    {item.badge}
                  </span>
                )}
              </NavLink>
            );
          })}
        </nav>

        {/* User info + WS status */}
        <div className="p-3 border-t border-[#30363d] space-y-2">
          <div className="flex items-center gap-2 text-xs text-[#8b949e]">
            <span className={`w-2 h-2 rounded-full ${wsStatusDot(wsStatus)}`} />
            <span>{wsStatus === 'connected' ? 'Live' : wsStatus === 'connecting' ? 'Connecting...' : 'Offline'}</span>
          </div>
          {user && (
            <div className="flex items-center justify-between">
              <div className="min-w-0">
                <p className="text-sm font-medium text-[#e1e4e8] truncate">{user.username}</p>
                <p className="text-xs text-[#8b949e]">{user.is_admin ? 'Admin' : 'User'}</p>
              </div>
              <button
                type="button"
                onClick={logout}
                className="text-xs text-[#8b949e] hover:text-[#f43f5e] transition-colors px-2 py-1 rounded"
                aria-label="Log out"
              >
                Logout
              </button>
            </div>
          )}
        </div>
      </aside>

      {/* Overlay on mobile */}
      {!collapsed && (
        <div
          className="lg:hidden fixed inset-0 z-30 bg-black/50"
          onClick={() => setCollapsed(true)}
          aria-hidden="true"
        />
      )}
    </>
  );
}
