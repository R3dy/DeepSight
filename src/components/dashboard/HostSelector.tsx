import { useState, useMemo } from 'react';
import type { HostStatus } from '../../types';

interface HostSelectorProps {
  hosts: Record<string, HostStatus>;
  currentHost: string | null;
  onSelect: (hostname: string) => void;
}

export function HostSelector({ hosts, currentHost, onSelect }: HostSelectorProps) {
  const [search, setSearch] = useState('');
  const [open, setOpen] = useState(false);

  const hostList = useMemo(() => {
    const entries = Object.entries(hosts).map(([name, info]) => ({
      hostname: name,
      status: info.status,
      last_seen: info.last_seen,
      alert_count: info.alert_count,
    }));

    // Sort: current host first, then online, then stale, then offline
    return entries.sort((a, b) => {
      if (a.hostname === currentHost) return -1;
      if (b.hostname === currentHost) return 1;
      const statusOrder: Record<string, number> = { online: 0, stale: 1, offline: 2 };
      return (statusOrder[a.status] ?? 3) - (statusOrder[b.status] ?? 3);
    });
  }, [hosts, currentHost]);

  const filtered = useMemo(() => {
    if (!search.trim()) return hostList;
    const lower = search.toLowerCase();
    return hostList.filter(h => h.hostname.toLowerCase().includes(lower));
  }, [hostList, search]);

  const selectedHost = currentHost ? hosts[currentHost] : null;

  const statusDot = (status: string) => {
    switch (status) {
      case 'online':
        return <span className="w-2 h-2 rounded-full bg-[#22c55e] shadow-[0_0_5px_#22c55e]" />;
      case 'stale':
        return <span className="w-2 h-2 rounded-full bg-[#f59e0b] shadow-[0_0_5px_#f59e0b]" />;
      default:
        return <span className="w-2 h-2 rounded-full bg-[#6b7280]" />;
    }
  };

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="flex items-center gap-2 px-3 py-2 rounded-lg border border-[#30363d] bg-[#161b22] text-sm text-[#e1e4e8] hover:border-[#a78bfa] transition-colors font-mono min-w-[140px]"
      >
        {selectedHost && statusDot(selectedHost.status)}
        <span className="truncate">{currentHost || 'Select host'}</span>
        <span className="text-[10px] text-[#6e7681] ml-auto">{open ? '▲' : '▼'}</span>
      </button>

      {open && (
        <>
          <div
            className="fixed inset-0 z-40"
            onClick={() => setOpen(false)}
          />
          <div className="absolute top-full left-0 mt-1 z-50 w-72 bg-[#161b22] border border-[#30363d] rounded-lg shadow-xl max-h-80 overflow-hidden">
            {/* Search input */}
            <div className="p-2 border-b border-[#30363d]">
              <input
                type="text"
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder="Filter hosts..."
                className="w-full px-2 py-1 text-xs bg-[#0f1117] border border-[#30363d] rounded text-[#e1e4e8] placeholder-[#6e7681] focus:border-[#a78bfa] outline-none"
                autoFocus
              />
            </div>

            {/* Host list */}
            <div className="max-h-64 overflow-y-auto">
              {filtered.length === 0 ? (
                <div className="px-3 py-4 text-xs text-[#6e7681] text-center">
                  No hosts found
                </div>
              ) : (
                filtered.map(host => (
                  <button
                    key={host.hostname}
                    type="button"
                    onClick={() => {
                      onSelect(host.hostname);
                      setOpen(false);
                      setSearch('');
                    }}
                    className={`w-full flex items-center gap-2 px-3 py-2 text-xs text-left hover:bg-[#1c2129] transition-colors ${
                      host.hostname === currentHost
                        ? 'bg-[#1c2129] border-l-2 border-[#a78bfa]'
                        : 'border-l-2 border-transparent'
                    }`}
                  >
                    {statusDot(host.status)}
                    <span className="text-[#e1e4e8] font-mono truncate flex-1">
                      {host.hostname}
                    </span>
                    <span className="text-[10px] text-[#8b949e] capitalize">
                      {host.status}
                    </span>
                    {host.alert_count != null && host.alert_count > 0 && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-[#f43f5e]/15 text-[#f43f5e] font-medium">
                        {host.alert_count}
                      </span>
                    )}
                  </button>
                ))
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
