import { ColoredBar } from '../charts/ColoredBar';
import type { DiskStats } from '../../types';

interface DiskWidgetProps {
  disks: DiskStats[];
  lastUpdated: string | null;
}

function diskColor(pct: number): string {
  if (pct >= 90) return '#ef4444';
  if (pct >= 75) return '#f97316';
  if (pct >= 50) return '#f59e0b';
  return '#22c55e';
}

const EXCLUDED_FSTYPES = new Set(['tmpfs', 'devtmpfs', 'squashfs', 'overlay', 'snapfuse']);

export function DiskWidget({ disks, lastUpdated }: DiskWidgetProps) {
  const filtered = disks.filter(d => !EXCLUDED_FSTYPES.has(d.fstype) && !d.mountpoint.startsWith('/snap/'));

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs text-[#8b949e]">
          {filtered.length} volume{filtered.length !== 1 ? 's' : ''}
        </span>
        {lastUpdated && (
          <span className="text-[10px] text-[#6e7681]">{lastUpdated}</span>
        )}
      </div>

      {filtered.length === 0 ? (
        <div className="text-xs text-[#6e7681] text-center py-4">No disk volumes</div>
      ) : (
        <div className="space-y-2 max-h-[220px] overflow-y-auto">
          {filtered.map((disk) => (
            <div key={`${disk.device}-${disk.mountpoint}`} className="text-xs">
              <div className="flex items-center justify-between mb-0.5">
                <div className="flex items-center gap-1.5 min-w-0">
                  <span className="text-[#e1e4e8] truncate">{disk.mountpoint}</span>
                  <span className="text-[#6e7681] font-mono text-[10px]">{disk.device}</span>
                </div>
                <span className="text-[#8b949e] font-mono ml-2 flex-shrink-0">
                  {disk.used_gb.toFixed(1)} / {disk.total_gb.toFixed(1)} GB
                </span>
              </div>
              <div className="flex items-center gap-2">
                <ColoredBar
                  value={disk.percent}
                  color={diskColor(disk.percent)}
                  showLabel={false}
                  className="flex-1"
                />
                <span className="text-[#6e7681] font-mono w-10 text-right text-[10px]">
                  {disk.percent.toFixed(0)}%
                </span>
              </div>
              {(disk.read_mbps != null || disk.write_mbps != null) && (
                <div className="flex gap-3 text-[10px] text-[#6e7681] mt-0.5">
                  <span>R: {disk.read_mbps?.toFixed(1) ?? '—'} MB/s</span>
                  <span>W: {disk.write_mbps?.toFixed(1) ?? '—'} MB/s</span>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
