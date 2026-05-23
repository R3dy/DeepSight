import { useState, useCallback } from 'react';
import { getColor } from '../charts/colors';
import type { ProcessInfo } from '../../types';

type SortColumn = 'name' | 'pid' | 'cpu' | 'ram' | 'ram_pct';
type ProcessWithExtras = ProcessInfo & {
  memory_gb?: number;
  memory_mb?: number;
  ram_percent?: number;
};

interface ProcessTableProps {
  processes: ProcessWithExtras[];
  onProcessClick: (pid: number) => void;
  onProcessHover: (pid: number, event: React.MouseEvent) => void;
  onProcessLeave: () => void;
  tab: 'ram' | 'cpu';
  onTabChange: (tab: 'ram' | 'cpu') => void;
  filterText?: string;
  showAll?: boolean;
}

export function ProcessTable({
  processes,
  onProcessClick,
  onProcessHover,
  onProcessLeave,
  tab,
  onTabChange,
  filterText = '',
  showAll = false,
}: ProcessTableProps) {
  const [sortCol, setSortCol] = useState<SortColumn>(tab === 'ram' ? 'ram' : 'cpu');
  const [sortDir, setSortDir] = useState<-1 | 1>(-1);

  const handleSort = useCallback((col: SortColumn) => {
    setSortCol(prev => {
      if (prev === col) {
        setSortDir(d => (d === 1 ? -1 : 1));
      } else {
        setSortDir(-1);
      }
      return col;
    });
  }, []);

  // Filter processes
  const filtered = processes.filter(p => {
    if (!filterText) return true;
    const lower = filterText.toLowerCase();
    return (
      p.name.toLowerCase().includes(lower) ||
      String(p.pid).includes(lower)
    );
  });

  // Sort processes
  const sorted = [...filtered].sort((a, b) => {
    let va: number | string = 0, vb: number | string = 0;
    switch (sortCol) {
      case 'name': va = a.name ?? ''; vb = b.name ?? ''; break;
      case 'pid': va = a.pid ?? 0; vb = b.pid ?? 0; break;
      case 'cpu': va = a.cpu_percent ?? 0; vb = b.cpu_percent ?? 0; break;
      case 'ram': va = a.mem_rss ?? 0; vb = b.mem_rss ?? 0; break;
      case 'ram_pct': va = a.mem_percent ?? 0; vb = b.mem_percent ?? 0; break;
      default: return 0;
    }
    if (typeof va === 'string' && typeof vb === 'string') return sortDir * va.localeCompare(vb);
    return sortDir * ((va as number) - (vb as number));
  });

  // Top 15 + "other" aggregation
  const TOP_N = 15;
  const displayProcesses = showAll ? sorted : sorted.slice(0, TOP_N);
  const otherCount = sorted.length - TOP_N;
  const hasOther = !showAll && otherCount > 0;

  // Aggregate "other" processes
  const otherTotalRam = hasOther
    ? sorted.slice(TOP_N).reduce((sum, p) => sum + (p.mem_rss ?? 0), 0)
    : 0;
  const otherTotalCpu = hasOther
    ? sorted.slice(TOP_N).reduce((sum, p) => sum + (p.cpu_percent ?? 0), 0)
    : 0;

  const isRamTab = tab === 'ram';

  const thClass = (col: SortColumn) =>
    `cursor-pointer hover:text-[#a78bfa] transition-colors select-none ${
      sortCol === col ? 'text-[#a78bfa]' : ''
    }`;

  const sortArrow = (col: SortColumn) =>
    sortCol === col ? (sortDir === 1 ? ' ▲' : ' ▼') : '';

  return (
    <div className="overflow-hidden">
      {/* Tabs */}
      <div className="flex gap-0 mb-2">
        <button
          type="button"
          onClick={() => onTabChange('ram')}
          className={`px-3 py-1 text-xs font-medium rounded-l-lg border border-[#30363d] transition-colors ${
            isRamTab
              ? 'bg-[#1c2129] text-[#a78bfa] border-[#a78bfa]'
              : 'text-[#8b949e] hover:text-[#e1e4e8]'
          }`}
        >
          RAM
        </button>
        <button
          type="button"
          onClick={() => onTabChange('cpu')}
          className={`px-3 py-1 text-xs font-medium rounded-r-lg border border-[#30363d] border-l-0 transition-colors ${
            !isRamTab
              ? 'bg-[#1c2129] text-[#a78bfa] border-[#a78bfa]'
              : 'text-[#8b949e] hover:text-[#e1e4e8]'
          }`}
        >
          CPU
        </button>
      </div>

      {/* Table */}
      <div className="max-h-[320px] overflow-y-auto">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-[#161b22] z-10">
            <tr className="border-b border-[#30363d] text-[#8b949e]">
              <th className={`text-left py-1.5 px-2 font-medium ${thClass('name')}`} onClick={() => handleSort('name')}>
                Process{sortArrow('name')}
              </th>
              <th className={`text-left py-1.5 px-2 font-medium ${thClass('pid')}`} onClick={() => handleSort('pid')}>
                PID{sortArrow('pid')}
              </th>
              {isRamTab ? (
                <>
                  <th className={`text-right py-1.5 px-2 font-medium ${thClass('ram')}`} onClick={() => handleSort('ram')}>
                    Memory{sortArrow('ram')}
                  </th>
                  <th className={`text-right py-1.5 px-2 font-medium ${thClass('ram_pct')}`} onClick={() => handleSort('ram_pct')}>
                    %RAM{sortArrow('ram_pct')}
                  </th>
                  <th className={`text-right py-1.5 px-2 font-medium ${thClass('cpu')}`} onClick={() => handleSort('cpu')}>
                    CPU{sortArrow('cpu')}
                  </th>
                </>
              ) : (
                <>
                  <th className={`text-right py-1.5 px-2 font-medium ${thClass('cpu')}`} onClick={() => handleSort('cpu')}>
                    CPU%{sortArrow('cpu')}
                  </th>
                  <th className={`text-right py-1.5 px-2 font-medium ${thClass('ram')}`} onClick={() => handleSort('ram')}>
                    RAM{sortArrow('ram')}
                  </th>
                  <th className={`text-right py-1.5 px-2 font-medium ${thClass('ram_pct')}`} onClick={() => handleSort('ram_pct')}>
                    %RAM{sortArrow('ram_pct')}
                  </th>
                </>
              )}
            </tr>
          </thead>
          <tbody>
            {displayProcesses.map((proc, i) => {
              const color = getColor(i);
              const memMb = proc.memory_mb ?? (proc.mem_rss ?? 0);
              const memGb = proc.memory_gb ?? (memMb / 1024);
              const cpuPct = proc.cpu_percent ?? 0;
              const ramPct = proc.ram_percent ?? proc.mem_percent ?? 0;

              return (
                <tr
                  key={`${proc.pid}-${i}`}
                  className="border-b border-[#21262d] hover:bg-[#1c2129] cursor-pointer transition-colors"
                  onClick={() => onProcessClick(proc.pid)}
                  onMouseEnter={e => onProcessHover(proc.pid, e)}
                  onMouseLeave={onProcessLeave}
                >
                  <td className="py-1.5 px-2">
                    <div className="flex items-center gap-1.5">
                      <div
                        className="w-1 h-3 rounded-full flex-shrink-0"
                        style={{ backgroundColor: color }}
                      />
                      <span className="text-[#e1e4e8] truncate max-w-[120px]">
                        {proc.name}
                      </span>
                    </div>
                  </td>
                  <td className="py-1.5 px-2 text-[#6e7681] font-mono">{proc.pid}</td>
                  {isRamTab ? (
                    <>
                      <td className="py-1.5 px-2 text-right font-mono text-[#8b949e]">
                        {memGb >= 0.1 ? `${memGb.toFixed(1)} GB` : `${memMb.toFixed(0)} MB`}
                      </td>
                      <td className="py-1.5 px-2 text-right font-mono font-semibold" style={{ color }}>
                        {ramPct.toFixed(1)}%
                      </td>
                      <td className="py-1.5 px-2 text-right font-mono text-[#8b949e]">
                        {cpuPct.toFixed(1)}%
                      </td>
                    </>
                  ) : (
                    <>
                      <td className="py-1.5 px-2 text-right font-mono font-semibold" style={{ color }}>
                        {cpuPct.toFixed(1)}%
                      </td>
                      <td className="py-1.5 px-2 text-right font-mono text-[#8b949e]">
                        {memMb > 0 ? `${memMb.toFixed(0)} MB` : '<1 MB'}
                      </td>
                      <td className="py-1.5 px-2 text-right font-mono text-[#8b949e]">
                        {ramPct.toFixed(1)}%
                      </td>
                    </>
                  )}
                </tr>
              );
            })}

            {/* "Other" aggregation row */}
            {hasOther && (
              <tr className="border-b border-[#21262d] text-[#6e7681] italic">
                <td className="py-1.5 px-2">
                  other ({otherCount} processes)
                </td>
                <td className="py-1.5 px-2 font-mono">0</td>
                {isRamTab ? (
                  <>
                    <td className="py-1.5 px-2 text-right font-mono">
                      {otherTotalRam >= 1024
                        ? `${(otherTotalRam / 1024).toFixed(1)} GB`
                        : `${otherTotalRam.toFixed(0)} MB`}
                    </td>
                    <td className="py-1.5 px-2 text-right font-mono">—</td>
                    <td className="py-1.5 px-2 text-right font-mono">
                      {otherTotalCpu.toFixed(1)}%
                    </td>
                  </>
                ) : (
                  <>
                    <td className="py-1.5 px-2 text-right font-mono">
                      {otherTotalCpu.toFixed(1)}%
                    </td>
                    <td className="py-1.5 px-2 text-right font-mono">
                      {otherTotalRam >= 1024
                        ? `${(otherTotalRam / 1024).toFixed(1)} GB`
                        : `${otherTotalRam.toFixed(0)} MB`}
                    </td>
                    <td className="py-1.5 px-2 text-right font-mono">—</td>
                  </>
                )}
              </tr>
            )}

            {sorted.length === 0 && (
              <tr>
                <td colSpan={isRamTab ? 5 : 5} className="py-4 text-center text-[#6e7681]">
                  No processes found
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Show All toggle */}
      {!showAll && sorted.length > TOP_N && (
        <div className="text-center mt-1">
          <span className="text-[10px] text-[#6e7681]">
            Showing top {TOP_N} of {sorted.length} processes
          </span>
        </div>
      )}
    </div>
  );
}
