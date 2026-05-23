import type { FileEvent } from '../../types';

interface FileIntegrityTableProps {
  events: FileEvent[];
  isLoading: boolean;
}

function relativeTime(ts: string): string {
  const diff = Date.now() - new Date(ts).getTime();
  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  return `${Math.floor(seconds / 3600)}h ago`;
}

function eventTypeColor(type: string): string {
  switch (type) {
    case 'created': return 'text-[#22c55e]';
    case 'modified': return 'text-[#f59e0b]';
    case 'deleted': return 'text-[#f43f5e]';
    default: return 'text-[#8b949e]';
  }
}

export function FileIntegrityTable({ events, isLoading }: FileIntegrityTableProps) {
  if (isLoading) {
    return (
      <div className="space-y-1">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="animate-pulse flex gap-2 p-1">
            <div className="w-12 h-3 bg-[#21262d] rounded" />
            <div className="w-16 h-3 bg-[#21262d] rounded" />
            <div className="flex-1 h-3 bg-[#21262d] rounded" />
          </div>
        ))}
      </div>
    );
  }

  if (events.length === 0) {
    return (
      <div className="text-center py-4 text-[#8b949e]">
        <div className="text-xl mb-1">📁</div>
        <p className="text-xs">No file integrity events in the last hour</p>
      </div>
    );
  }

  return (
    <div className="max-h-[200px] overflow-y-auto">
      <table className="w-full text-xs">
        <thead className="sticky top-0 bg-[#161b22]">
          <tr className="text-[#8b949e] border-b border-[#30363d]">
            <th className="text-left py-1.5 px-2">Time</th>
            <th className="text-left py-1.5 px-2">Type</th>
            <th className="text-left py-1.5 px-2">Path</th>
            <th className="text-left py-1.5 px-2">Process</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event, i) => (
            <tr key={i} className="border-b border-[#21262d]/50">
              <td className="py-1 px-2 text-[#6e7681] whitespace-nowrap">
                {relativeTime(event.timestamp)}
              </td>
              <td className={`py-1 px-2 font-medium capitalize ${eventTypeColor(event.event_type)}`}>
                {event.event_type}
              </td>
              <td className="py-1 px-2 text-[#e1e4e8] font-mono text-[10px] truncate max-w-[200px]">
                {event.path}
              </td>
              <td className="py-1 px-2 text-[#8b949e] truncate max-w-[120px]">
                {event.process}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
