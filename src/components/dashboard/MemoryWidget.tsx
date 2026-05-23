import { GaugeChart } from '../charts/GaugeChart';
import type { MemoryStats } from '../../types';

interface MemoryWidgetProps {
  memory: MemoryStats;
  lastUpdated: string | null;
}

export function MemoryWidget({ memory, lastUpdated }: MemoryWidgetProps) {
  const usedPct = memory.percent;
  const hardUsed = memory.hard_used_gb ?? 0;
  const kernel = memory.kernel_gb ?? 0;
  const cached = memory.cached_gb ?? 0;
  const buffers = memory.buffers_gb ?? 0;
  const free = memory.free_gb ?? 0;
  const total = memory.total_gb ?? 0;

  const segments = [
    { label: 'Hard Used', value: hardUsed, color: '#8b5cf6' },
    { label: 'Kernel', value: kernel, color: '#ef4444' },
    { label: 'Cached', value: cached, color: '#f59e0b' },
    { label: 'Buffers', value: buffers, color: '#f97316' },
    { label: 'Free', value: free, color: '#22c55e' },
  ].filter(s => s.value > 0);

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <GaugeChart value={usedPct} size={100} colorThresholds={{ green: 40, yellow: 60, orange: 80 }} />
          <div>
            <div className="text-lg font-bold text-[#e1e4e8]">{usedPct.toFixed(1)}%</div>
            <div className="text-xs text-[#8b949e]">{memory.used_gb.toFixed(1)} / {total.toFixed(1)} GB</div>
          </div>
        </div>
        {lastUpdated && (
          <span className="text-[10px] text-[#6e7681]">{lastUpdated}</span>
        )}
      </div>

      {/* RAM breakdown bar */}
      <div className="flex h-3 rounded-full overflow-hidden">
        {segments.map((s, i) => (
          <div
            key={i}
            className="h-full transition-all duration-300"
            style={{
              width: `${(s.value / total) * 100}%`,
              backgroundColor: s.color,
            }}
            title={`${s.label}: ${s.value.toFixed(1)} GB`}
          />
        ))}
      </div>

      <div className="flex flex-wrap gap-x-4 gap-y-1 text-[10px]">
        {segments.map((s, i) => (
          <div key={i} className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full" style={{ backgroundColor: s.color }} />
            <span className="text-[#8b949e]">{s.label}</span>
            <span className="text-[#e1e4e8] font-mono">{s.value.toFixed(1)} GB</span>
          </div>
        ))}
      </div>

      {memory.swap_total != null && memory.swap_total > 0 && (
        <div className="text-[10px] text-[#6e7681]">
          Swap: {memory.swap_used?.toFixed(1) ?? '?'} / {memory.swap_total.toFixed(1)} GB
          {memory.swap_percent != null && ` (${memory.swap_percent.toFixed(0)}%)`}
        </div>
      )}
    </div>
  );
}
