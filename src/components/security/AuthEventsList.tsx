import type { AuthEvent } from '../../types';

interface AuthEventsListProps {
  events: AuthEvent[];
  isLoading: boolean;
}

function relativeTime(ts: string): string {
  const diff = Date.now() - new Date(ts).getTime();
  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  return `${Math.floor(seconds / 3600)}h ago`;
}

function eventIcon(type: string): string {
  if (type.includes('fail') || type.includes('invalid')) return '❌';
  if (type.includes('sudo')) return '⚠️';
  return '✅';
}

export function AuthEventsList({ events, isLoading }: AuthEventsListProps) {
  if (isLoading) {
    return (
      <div className="space-y-1">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="animate-pulse flex gap-2 p-1">
            <div className="w-4 h-4 bg-[#21262d] rounded" />
            <div className="flex-1 h-3 bg-[#21262d] rounded" />
          </div>
        ))}
      </div>
    );
  }

  if (events.length === 0) {
    return (
      <div className="text-center py-4 text-[#8b949e]">
        <div className="text-xl mb-1">🔒</div>
        <p className="text-xs">No recent auth events</p>
      </div>
    );
  }

  return (
    <div className="space-y-1 max-h-[250px] overflow-y-auto">
      {events.map((event, i) => (
        <div key={i} className="flex items-center gap-2 text-xs py-1 border-b border-[#21262d]/50 last:border-0">
          <span className="text-xs">{eventIcon(event.event_type)}</span>
          <span className="font-medium text-[#e1e4e8] min-w-[60px]">{event.username}</span>
          <span className="text-[#8b949e] text-[10px] truncate max-w-[100px]">{event.source_ip}</span>
          <span className="text-[#6e7681] text-[10px] truncate max-w-[120px]">
            {event.detail?.substring(0, 40) ?? '—'}
          </span>
          {event.failure_count != null && event.failure_count > 1 && (
            <span className="text-[10px] px-1 py-0.5 rounded bg-[#f43f5e]/15 text-[#f43f5e] font-mono">
              x{event.failure_count}
            </span>
          )}
          <span className="text-[10px] text-[#6e7681] ml-auto">{relativeTime(event.timestamp)}</span>
        </div>
      ))}
    </div>
  );
}
