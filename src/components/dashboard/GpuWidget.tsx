import { GaugeChart } from '../charts/GaugeChart';
import type { GpuStats } from '../../types';

interface GpuWidgetProps {
  gpu?: GpuStats;
  lastUpdated: string | null;
}

export function GpuWidget({ gpu, lastUpdated }: GpuWidgetProps) {
  // No GPU present
  if (!gpu || !gpu.vram_total || gpu.vram_total <= 0) {
    return (
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-[100px] h-[100px] flex items-center justify-center rounded-full border-2 border-dashed border-[#30363d]">
              <span className="text-2xl text-[#6e7681]">—</span>
            </div>
            <div>
              <div className="text-sm font-medium text-[#8b949e]">No GPU detected</div>
              <div className="text-xs text-[#6e7681]">GPU monitoring unavailable</div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  const vramPct = gpu.vram_total > 0
    ? ((gpu.vram_used ?? 0) / gpu.vram_total) * 100
    : 0;

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <GaugeChart value={vramPct} size={100} />
          <div>
            <div className="text-sm font-bold text-[#e1e4e8]">{gpu.name ?? 'GPU'}</div>
            <div className="text-xs text-[#8b949e]">
              VRAM: {(gpu.vram_used ?? 0).toFixed(1)} / {(gpu.vram_total ?? 0).toFixed(1)} GB
            </div>
            {gpu.usage_percent != null && (
              <div className="text-xs text-[#06b6d4]">Util: {gpu.usage_percent.toFixed(1)}%</div>
            )}
            {gpu.temperature != null && (
              <div className="text-xs text-[#f97316]">🌡 {gpu.temperature.toFixed(1)}°C</div>
            )}
          </div>
        </div>
        {lastUpdated && (
          <span className="text-[10px] text-[#6e7681]">{lastUpdated}</span>
        )}
      </div>
    </div>
  );
}
