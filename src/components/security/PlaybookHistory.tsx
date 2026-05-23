import { useQuery } from '@tanstack/react-query';
import { getPlaybookHistory, getPlaybooks } from '../../api/playbooks';
import type { PlaybookHistoryEntry, PlaybookInfo } from '../../api/playbooks';

function statusBadge(status: string) {
  const map: Record<string, { bg: string; text: string }> = {
    success: { bg: 'bg-[#238636]/15', text: 'text-[#3fb950]' },
    partial: { bg: 'bg-[#d29922]/15', text: 'text-[#d29922]' },
    error: { bg: 'bg-[#da3633]/15', text: 'text-[#f85149]' },
    running: { bg: 'bg-[#a78bfa]/15', text: 'text-[#a78bfa]' },
  };
  return map[status] || { bg: 'bg-[#8b949e]/15', text: 'text-[#8b949e]' };
}

function relativeTime(ts: string): string {
  const diff = Date.now() - new Date(ts).getTime();
  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function HistoryRow({ entry }: { entry: PlaybookHistoryEntry }) {
  return (
    <tr className="border-t border-[#21262d] hover:bg-[#1c2129] transition-colors">
      <td className="px-3 py-2 text-xs text-[#a78bfa] font-mono">
        {entry.alert_id ?? '—'}
      </td>
      <td className="px-3 py-2 text-xs text-[#8b949e]">
        {relativeTime(entry.timestamp)}
      </td>
      <td className="px-3 py-2">
        <div className="flex flex-wrap gap-1">
          {entry.playbooks_run.map((pb, i) => {
            const st = statusBadge(pb.status);
            return (
              <span
                key={`${pb.name}-${i}`}
                className={`text-[10px] px-1.5 py-0.5 rounded ${st.bg} ${st.text}`}
              >
                {pb.name}: {pb.status}
              </span>
            );
          })}
        </div>
      </td>
      <td className="px-3 py-2 text-[10px] text-[#484f58]">
        {entry.timestamp}
      </td>
    </tr>
  );
}

function HistorySkeleton() {
  return (
    <div className="space-y-2 animate-pulse">
      {[1, 2, 3, 4, 5].map(i => (
        <div key={i} className="flex gap-4 px-3 py-2">
          <div className="h-3 w-10 bg-[#21262d] rounded" />
          <div className="h-3 w-16 bg-[#21262d] rounded" />
          <div className="h-3 w-40 bg-[#21262d] rounded" />
        </div>
      ))}
    </div>
  );
}

/** Available playbooks summary card */
function PlaybookCatalog() {
  const { data, isLoading } = useQuery({
    queryKey: ['playbooks'],
    queryFn: getPlaybooks,
    staleTime: 60000,
  });

  const playbooks: PlaybookInfo[] = data?.ok ? data.data.data : [];

  if (isLoading) {
    return (
      <div className="rounded border border-[#30363d] bg-[#0d1117] p-3 animate-pulse">
        <div className="h-4 w-32 bg-[#21262d] rounded mb-2" />
        <div className="h-3 w-64 bg-[#21262d] rounded" />
      </div>
    );
  }

  return (
    <div className="rounded border border-[#30363d] bg-[#0d1117] p-3">
      <h4 className="text-xs font-semibold text-[#e1e4e8] mb-2">📋 Available Playbooks ({playbooks.length})</h4>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
        {playbooks.map(pb => (
          <div key={pb.name} className="rounded bg-[#161b22] border border-[#21262d] px-3 py-2">
            <div className="text-xs font-medium text-[#a78bfa] font-mono">{pb.name}</div>
            <div className="text-[10px] text-[#8b949e] mt-0.5">{pb.description}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

export function PlaybookHistory() {
  const { data, isLoading } = useQuery({
    queryKey: ['playbookHistory'],
    queryFn: () => getPlaybookHistory(50, 0),
    refetchInterval: 15000,
    staleTime: 10000,
  });

  const history = data?.ok ? data.data.data : null;

  return (
    <div className="space-y-4">
      {/* Playbook catalog */}
      <PlaybookCatalog />

      {/* Run history */}
      <div className="rounded-lg border border-[#30363d] bg-[#161b22]">
        <div className="flex items-center justify-between px-4 py-3 border-b border-[#21262d]">
          <h3 className="text-sm font-semibold text-[#e1e4e8]">📜 Playbook Run History</h3>
          <span className="text-[10px] text-[#8b949e]">
            {history ? `${history.total} runs` : '...'}
          </span>
        </div>

        {isLoading ? (
          <div className="p-4">
            <HistorySkeleton />
          </div>
        ) : !history || history.history.length === 0 ? (
          <div className="p-4 text-xs text-[#8b949e]">
            No playbook runs recorded yet. Playbooks execute automatically when matching alerts fire.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-[#21262d] text-[10px] text-[#8b949e] uppercase tracking-wider">
                  <th className="px-3 py-2 font-medium">Alert ID</th>
                  <th className="px-3 py-2 font-medium">When</th>
                  <th className="px-3 py-2 font-medium">Playbooks</th>
                  <th className="px-3 py-2 font-medium">Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {history.history.map((entry, i) => (
                  <HistoryRow key={`${entry.alert_id}-${i}`} entry={entry} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
