import { SeverityBadge } from '../charts/SeverityBadge';
import type { Alert } from '../../types';

interface AlertListProps {
  alerts: Alert[];
  isLoading: boolean;
  acknowledgedIds: Set<number>;
  onAcknowledge: (id: number) => void;
}

function relativeTime(ts: string): string {
  const diff = Date.now() - new Date(ts).getTime();
  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export function AlertList({ alerts, isLoading, acknowledgedIds, onAcknowledge }: AlertListProps) {
  if (isLoading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 3 }).map((_, i) => (
          <div key={i} className="rounded-lg border border-[#30363d] bg-[#161b22] p-3 animate-pulse">
            <div className="h-4 w-32 bg-[#21262d] rounded mb-1" />
            <div className="h-3 w-48 bg-[#21262d] rounded" />
          </div>
        ))}
      </div>
    );
  }

  if (alerts.length === 0) {
    return (
      <div className="text-center py-6 text-[#8b949e]">
        <div className="text-2xl mb-2">✅</div>
        <p className="text-xs">No active alerts</p>
      </div>
    );
  }

  return (
    <div className="space-y-2 max-h-[400px] overflow-y-auto">
      {alerts.map(alert => {
        const isAcked = alert.acknowledged || acknowledgedIds.has(alert.id);
        return (
          <div
            key={alert.id}
            className={`rounded-lg border border-[#30363d] bg-[#161b22] p-3 transition-colors ${
              isAcked ? 'opacity-60' : ''
            }`}
          >
            <div className="flex items-start justify-between gap-2">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap mb-1">
                  <SeverityBadge severity={alert.severity} size="sm" />
                  {alert.mitre_technique && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#a78bfa]/15 text-[#a78bfa] font-mono">
                      {alert.mitre_technique}
                    </span>
                  )}
                  <span className="text-[10px] text-[#6e7681]">{relativeTime(alert.timestamp)}</span>
                </div>
                <h4 className="text-sm font-medium text-[#e1e4e8] mb-0.5">{alert.title}</h4>
                <p className="text-xs text-[#8b949e] line-clamp-2">{alert.description}</p>
                <div className="flex items-center gap-3 mt-1.5 text-[10px] text-[#6e7681]">
                  {alert.source_host && <span>🖥 {alert.source_host}</span>}
                  {alert.source_ip && <span>🌐 {alert.source_ip}</span>}
                  {alert.process_name && (
                    <span>⚙️ {alert.process_name}{alert.process_pid != null ? `:${alert.process_pid}` : ''}</span>
                  )}
                  {alert.category && <span className="uppercase">{alert.category}</span>}
                </div>
              </div>

              <button
                type="button"
                onClick={() => onAcknowledge(alert.id)}
                disabled={isAcked}
                className={`flex-shrink-0 px-2 py-1 text-[10px] font-medium rounded transition-colors ${
                  isAcked
                    ? 'text-[#6e7681] cursor-default'
                    : 'text-[#a78bfa] hover:bg-[#a78bfa]/10 border border-[#a78bfa]/30 hover:border-[#a78bfa]'
                }`}
              >
                {isAcked ? 'Acknowledged' : '✓ Acknowledge'}
              </button>
            </div>
          </div>
        );
      })}
    </div>
  );
}
