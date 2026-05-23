import { useState, type ReactNode } from 'react';

interface WidgetCardProps {
  title: string;
  icon: string;
  badge?: ReactNode;
  children: ReactNode;
  expandAction?: () => void;
  defaultCollapsed?: boolean;
  onCollapseChange?: (collapsed: boolean) => void;
}

export function WidgetCard({
  title,
  icon,
  badge,
  children,
  expandAction,
  defaultCollapsed = false,
  onCollapseChange,
}: WidgetCardProps) {
  const [collapsed, setCollapsed] = useState(defaultCollapsed);

  const toggleCollapse = () => {
    const next = !collapsed;
    setCollapsed(next);
    onCollapseChange?.(next);
  };

  return (
    <div className="rounded-lg border border-[#30363d] bg-[#161b22] overflow-hidden">
      <div className="flex items-center justify-between px-3 py-2 border-b border-[#30363d]">
        <button
          type="button"
          onClick={toggleCollapse}
          className="flex items-center gap-2 text-sm font-semibold text-[#e1e4e8] hover:text-[#a78bfa] transition-colors"
        >
          <span className="text-xs">{collapsed ? '▶' : '▼'}</span>
          <span className="mr-1">{icon}</span>
          {title}
        </button>
        <div className="flex items-center gap-2">
          {badge}
          {expandAction && (
            <button
              type="button"
              onClick={e => { e.stopPropagation(); expandAction(); }}
              className="text-xs text-[#6e7681] hover:text-[#a78bfa] transition-colors px-1"
              title="Deep dive"
            >
              ⛶
            </button>
          )}
        </div>
      </div>
      {!collapsed && <div className="p-3">{children}</div>}
    </div>
  );
}
