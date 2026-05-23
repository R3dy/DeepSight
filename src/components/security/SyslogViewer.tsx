import { useState } from 'react';
import type { SyslogEvent } from '../../types';

interface SyslogViewerProps {
  events: SyslogEvent[];
  hosts: string[];
  facilities: string[];
  isLoading: boolean;
  onFilterChange: (host?: string, facility?: string) => void;
  selectedHost?: string;
  selectedFacility?: string;
}

function relativeTime(ts: string): string {
  const diff = Date.now() - new Date(ts).getTime();
  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  return `${Math.floor(seconds / 3600)}h ago`;
}

function severityBadge(severity: string): { color: string; bg: string } {
  const s = severity.toLowerCase();
  if (s.includes('crit') || s.includes('emerg') || s.includes('alert')) return { color: '#dc2626', bg: 'bg-[#dc2626]/15' };
  if (s.includes('err')) return { color: '#ea580c', bg: 'bg-[#ea580c]/15' };
  if (s.includes('warn')) return { color: '#f59e0b', bg: 'bg-[#f59e0b]/15' };
  if (s.includes('info') || s.includes('notice')) return { color: '#3b82f6', bg: 'bg-[#3b82f6]/15' };
  return { color: '#6b7280', bg: 'bg-[#6b7280]/15' };
}

export function SyslogViewer({
  events,
  hosts,
  facilities,
  isLoading,
  onFilterChange,
  selectedHost,
  selectedFacility,
}: SyslogViewerProps) {
  const [paused, setPaused] = useState(false);

  if (isLoading) {
    return (
      <div className="space-y-1">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="animate-pulse flex gap-2 p-1">
            <div className="w-16 h-3 bg-[#21262d] rounded" />
            <div className="w-12 h-3 bg-[#21262d] rounded" />
            <div className="flex-1 h-3 bg-[#21262d] rounded" />
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {/* Filters */}
      <div className="flex items-center gap-2 flex-wrap">
        <select
          value={selectedHost ?? ''}
          onChange={e => onFilterChange(e.target.value || undefined, selectedFacility)}
          className="px-2 py-1 text-[10px] bg-[#0f1117] border border-[#30363d] rounded text-[#e1e4e8] focus:border-[#a78bfa] outline-none"
        >
          <option value="">All hosts</option>
          {hosts.map(h => (
            <option key={h} value={h}>{h}</option>
          ))}
        </select>
        <select
          value={selectedFacility ?? ''}
          onChange={e => onFilterChange(selectedHost, e.target.value || undefined)}
          className="px-2 py-1 text-[10px] bg-[#0f1117] border border-[#30363d] rounded text-[#e1e4e8] focus:border-[#a78bfa] outline-none"
        >
          <option value="">All facilities</option>
          {facilities.map(f => (
            <option key={f} value={f}>{f}</option>
          ))}
        </select>
        <button
          type="button"
          onClick={() => setPaused(!paused)}
          className={`px-2 py-1 text-[10px] font-medium rounded border transition-colors ${
            paused
              ? 'border-[#f59e0b] text-[#f59e0b]'
              : 'border-[#30363d] text-[#8b949e] hover:border-[#a78bfa]'
          }`}
        >
          {paused ? '▶ Resume' : '⏸ Pause'}
        </button>
        <span className="text-[10px] text-[#8b949e] ml-auto">
          {events.length} events
        </span>
      </div>

      {/* Events */}
      {events.length === 0 ? (
        <div className="text-center py-6 text-[#8b949e]">
          <div className="text-xl mb-1">📋</div>
          <p className="text-xs">No syslog events received</p>
          <p className="text-[10px] mt-1">Point a device at this server on UDP port 514.</p>
        </div>
      ) : (
        <div className="max-h-[300px] overflow-y-auto space-y-0.5">
          {events.map((event, i) => {
            const sev = severityBadge(event.severity);
            return (
              <div key={i} className="flex items-start gap-2 text-[10px] py-1 border-b border-[#21262d]/50 last:border-0">
                <span className="text-[#6e7681] whitespace-nowrap w-12">
                  {relativeTime(event.timestamp)}
                </span>
                <span
                  className={`px-1 py-0.5 rounded text-[9px] font-medium uppercase whitespace-nowrap ${sev.bg}`}
                  style={{ color: sev.color }}
                >
                  {event.severity}
                </span>
                <span className="text-[#a78bfa] font-mono text-[9px] truncate max-w-[100px]">
                  {event.source_host.substring(0, 20)}
                </span>
                <span className="text-[#8b949e] text-[9px] whitespace-nowrap">
                  {event.facility}
                </span>
                <span className="text-[#e1e4e8] truncate flex-1">
                  {event.message.substring(0, 200)}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
