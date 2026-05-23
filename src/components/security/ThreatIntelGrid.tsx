import type { ThreatIntelStatus } from '../../types';

interface ThreatIntelGridProps {
  data: ThreatIntelStatus | null;
  isLoading: boolean;
  isError: boolean;
}

function statusIcon(status: string): string {
  switch (status) {
    case 'loaded': return '✅';
    case 'stale': return '⚠️';
    case 'error': return '❌';
    case 'disabled': return '⏸️';
    default: return '⏳';
  }
}

function statusColor(status: string): string {
  switch (status) {
    case 'loaded': return 'border-[#22c55e] bg-[#22c55e]/5';
    case 'stale': return 'border-[#f59e0b] bg-[#f59e0b]/5';
    case 'error': return 'border-[#f43f5e] bg-[#f43f5e]/5';
    case 'disabled': return 'border-[#6b7280] bg-[#6b7280]/5';
    default: return 'border-[#30363d] bg-[#161b22]';
  }
}

function relativeTime(ts: number | undefined): string {
  if (!ts) return '—';
  const diff = Math.floor((Date.now() - ts * 1000) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  return `${Math.floor(diff / 3600)}h ago`;
}

export function ThreatIntelGrid({ data, isLoading, isError }: ThreatIntelGridProps) {
  if (isLoading) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-2">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="rounded-lg border border-[#30363d] bg-[#161b22] p-3 animate-pulse">
            <div className="h-3 w-20 bg-[#21262d] rounded mb-2" />
            <div className="h-4 w-12 bg-[#21262d] rounded" />
          </div>
        ))}
      </div>
    );
  }

  if (isError || !data) {
    return (
      <div className="text-center py-4 text-[#f43f5e]">
        <div className="text-xl mb-1">⚠️</div>
        <p className="text-xs">Threat intel data unavailable</p>
      </div>
    );
  }

  const feeds = data.feeds ?? [];

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <span className="text-xs text-[#8b949e]">
          {data.loaded_count}/{data.total_feeds} feeds loaded
        </span>
        <div className="flex gap-3 text-[10px] text-[#8b949e]">
          <span>Observed IPs: {data.observed_ips}</span>
          <span>Domains: {data.observed_domains}</span>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-2">
        {feeds.map((feed, i) => (
          <div
            key={i}
            className={`rounded-lg border p-3 ${statusColor(feed.status)}`}
          >
            <div className="flex items-center gap-1.5 mb-1">
              <span className="text-xs">{statusIcon(feed.status)}</span>
              <span className="text-[10px] font-medium text-[#e1e4e8] truncate">{feed.name}</span>
            </div>
            <div className="text-lg font-bold text-[#e1e4e8]">
              {feed.indicator_count}
            </div>
            <div className="text-[10px] text-[#6e7681]">
              {feed.status === 'error' && feed.error_message ? (
                <span className="text-[#f43f5e]">{feed.error_message.substring(0, 40)}</span>
              ) : (
                relativeTime(feed.last_updated)
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
