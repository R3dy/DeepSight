import { GaugeChart } from '../charts/GaugeChart';
import { getColor } from '../charts/colors';
import type { CpuStats } from '../../types';

interface CpuWidgetProps {
  cpu: CpuStats;
  lastUpdated: string | null;
}

export function CpuWidget({ cpu, lastUpdated }: CpuWidgetProps) {
  const pct = cpu.percent;
  const cores = cpu.per_cpu ?? [];

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <GaugeChart value={pct} size={100} colorThresholds={{ green: 25, yellow: 50, orange: 75 }} />
          <div>
            <div className="text-lg font-bold text-[#e1e4e8]">{pct.toFixed(1)}%</div>
            <div className="text-xs text-[#8b949e]">
              {cpu.count} core{cpu.count !== 1 ? 's' : ''}
              {cpu.freq_current != null && ` · ${cpu.freq_current} MHz`}
            </div>
            {cpu.temperature != null && (
              <div className="text-xs text-[#f97316] mt-0.5">🌡 {cpu.temperature.toFixed(1)}°C</div>
            )}
          </div>
        </div>
        {lastUpdated && (
          <span className="text-[10px] text-[#6e7681]">{lastUpdated}</span>
        )}
      </div>

      {/* Per-core bars */}
      {cores.length > 0 && (
        <div className="flex items-end gap-0.5 h-12">
          {cores.map((corePct, i) => (
            <div key={i} className="flex-1 flex flex-col items-center justify-end h-full">
              <div
                className="w-full rounded-t-sm transition-all duration-300 min-h-[2px]"
                style={{
                  height: `${Math.max(2, corePct)}%`,
                  backgroundColor: getColor(i),
                }}
                title={`Core ${i}: ${corePct.toFixed(1)}%`}
              />
            </div>
          ))}
        </div>
      )}

      {cpu.load_avg && (
        <div className="flex gap-3 text-[10px] text-[#6e7681]">
          <span>Load: {cpu.load_avg['1min'].toFixed(2)} / {cpu.load_avg['5min'].toFixed(2)} / {cpu.load_avg['15min'].toFixed(2)}</span>
        </div>
      )}
    </div>
  );
}
