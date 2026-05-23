import { useQuery } from '@tanstack/react-query';
import { getDeepDive } from '../../api';
import { MemoryWidget } from './MemoryWidget';
import { CpuWidget } from './CpuWidget';
import { GpuWidget } from './GpuWidget';
import { DiskWidget } from './DiskWidget';
import { NetworkWidget } from './NetworkWidget';
import { ColoredBar } from '../charts/ColoredBar';
import type { PssUssProcess } from '../../types';

interface DeepDiveModalProps {
  section: 'ram' | 'cpu' | 'gpu' | 'disk' | 'network';
  host?: string | null;
  onClose: () => void;
  onProcessClick: (pid: number) => void;
  onProcessHover: (pid: number, e: React.MouseEvent) => void;
  onProcessLeave: () => void;
}

function PssUssTable({
  processes,
  onProcessClick,
  onProcessHover,
  onProcessLeave,
}: {
  processes: PssUssProcess[];
  onProcessClick: (pid: number) => void;
  onProcessHover: (pid: number, e: React.MouseEvent) => void;
  onProcessLeave: () => void;
}) {
  return (
    <div className="max-h-[400px] overflow-y-auto">
      <table className="w-full text-xs">
        <thead className="sticky top-0 bg-[#161b22]">
          <tr className="text-[#8b949e] border-b border-[#30363d]">
            <th className="text-left py-1.5 px-2">PID</th>
            <th className="text-left py-1.5 px-2">User</th>
            <th className="text-left py-1.5 px-2">Process</th>
            <th className="text-left py-1.5 px-2">State</th>
            <th className="text-right py-1.5 px-2">Thr</th>
            <th className="text-right py-1.5 px-2">PSS</th>
            <th className="text-right py-1.5 px-2">RSS</th>
            <th className="text-right py-1.5 px-2">USS</th>
            <th className="text-right py-1.5 px-2">CPU%</th>
          </tr>
        </thead>
        <tbody>
          {processes.map((proc, i) => (
            <tr
              key={i}
              className="border-b border-[#21262d] hover:bg-[#1c2129] cursor-pointer"
              onClick={() => onProcessClick(proc.pid)}
              onMouseEnter={e => onProcessHover(proc.pid, e)}
              onMouseLeave={onProcessLeave}
            >
              <td className="py-1.5 px-2 text-[#6e7681] font-mono">{proc.pid}</td>
              <td className="py-1.5 px-2 text-[#8b949e]">{proc.user}</td>
              <td className="py-1.5 px-2 text-[#e1e4e8] truncate max-w-[120px]">{proc.name}</td>
              <td className="py-1.5 px-2 text-[#8b949e]">{proc.state}</td>
              <td className="py-1.5 px-2 text-right text-[#8b949e]">{proc.threads}</td>
              <td className="py-1.5 px-2 text-right text-[#a78bfa] font-mono">{proc.pss_mb.toFixed(1)} MB</td>
              <td className="py-1.5 px-2 text-right text-[#8b949e] font-mono">{proc.rss_mb.toFixed(1)} MB</td>
              <td className="py-1.5 px-2 text-right text-[#8b949e] font-mono">{proc.uss_mb.toFixed(1)} MB</td>
              <td className="py-1.5 px-2 text-right text-[#f97316] font-mono">{proc.cpu_percent.toFixed(1)}%</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function DeepDiveModal({
  section,
  host,
  onClose,
  onProcessClick,
  onProcessHover,
  onProcessLeave,
}: DeepDiveModalProps) {
  const { data: result, isLoading } = useQuery({
    queryKey: ['deepdive', host],
    queryFn: () => getDeepDive(host ?? undefined),
    staleTime: 30000,
  });

  const data = result?.ok ? result.data : null;

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') onClose();
  };

  const titles: Record<string, string> = {
    ram: '🧠 RAM Deep Dive',
    cpu: '⚙️ CPU Deep Dive',
    gpu: '🎮 GPU Deep Dive',
    disk: '💾 Disk Deep Dive',
    network: '🌐 Network Deep Dive',
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onClick={onClose}
      onKeyDown={handleKeyDown}
    >
      <div
        className="bg-[#161b22] border border-[#30363d] rounded-xl w-full max-w-4xl max-h-[85vh] overflow-y-auto shadow-2xl"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-[#30363d] sticky top-0 bg-[#161b22] z-10">
          <h3 className="text-lg font-bold text-[#e1e4e8]">
            {titles[section] ?? titles.ram}
          </h3>
          <button
            type="button"
            onClick={onClose}
            className="text-[#8b949e] hover:text-[#f43f5e] text-xl leading-none px-2"
          >
            ✕
          </button>
        </div>

        {/* Content */}
        <div className="p-4">
          {isLoading ? (
            <div className="text-center py-8 text-[#8b949e] animate-pulse">Loading...</div>
          ) : !data ? (
            <div className="text-center py-8 text-[#f43f5e]">Failed to load data</div>
          ) : (
            <>
              {/* RAM Section */}
              {section === 'ram' && (
                <div className="space-y-4">
                  <MemoryWidget memory={data.memory} lastUpdated={null} />
                  {data.swappiness != null && (
                    <div className="text-xs text-[#8b949e]">
                      Swappiness: {data.swappiness}
                    </div>
                  )}

                  {/* Meminfo breakdown */}
                  {data.meminfo && (
                    <div className="space-y-1">
                      <h4 className="text-xs font-semibold text-[#a78bfa]">/proc/meminfo</h4>
                      <div className="grid grid-cols-2 md:grid-cols-3 gap-1">
                        {Object.entries(data.meminfo).map(([key, val]) => (
                          <div key={key} className="text-xs flex justify-between p-1 bg-[#0f1117] rounded">
                            <span className="text-[#8b949e]">{key}</span>
                            <span className="font-mono text-[#e1e4e8]">
                              {typeof val === 'number' && val >= 1024 * 1024
                                ? `${(val / (1024 * 1024 * 1024)).toFixed(2)} GB`
                                : typeof val === 'number' && val >= 1024
                                  ? `${(val / 1024).toFixed(1)} MB`
                                  : val}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Memory pressure */}
                  {data.memory_pressure && (
                    <div className="text-xs text-[#8b949e]">
                      Memory Pressure (PSI): some={data.memory_pressure.some_avg10?.toFixed(1)}%
                    </div>
                  )}

                  {/* Hugepages */}
                  {data.hugepages_total != null && (
                    <div className="text-xs text-[#8b949e]">
                      Hugepages: {data.hugepages_free ?? '?'} free / {data.hugepages_total} total
                      {data.hugepages_reserved != null && ` (${data.hugepages_reserved} reserved)`}
                    </div>
                  )}

                  {/* PSS/USS Table */}
                  {data.pss_uss_processes && data.pss_uss_processes.length > 0 && (
                    <div className="space-y-2">
                      <h4 className="text-xs font-semibold text-[#a78bfa]">
                        Top 20 Processes (PSS/USS)
                      </h4>
                      <PssUssTable
                        processes={data.pss_uss_processes.slice(0, 20)}
                        onProcessClick={onProcessClick}
                        onProcessHover={onProcessHover}
                        onProcessLeave={onProcessLeave}
                      />
                    </div>
                  )}
                </div>
              )}

              {/* CPU Section */}
              {section === 'cpu' && (
                <div className="space-y-4">
                  <CpuWidget cpu={data.cpu} lastUpdated={null} />
                  {data.cpu.freq_current != null && (
                    <div className="text-xs text-[#8b949e]">
                      Frequency: {data.cpu.freq_current} MHz
                      {data.cpu.freq_max != null && ` (max ${data.cpu.freq_max} MHz)`}
                    </div>
                  )}
                  {data.cpu.temperature != null && (
                    <div className="text-xs text-[#f97316]">
                      Temperature: {data.cpu.temperature.toFixed(1)}°C
                    </div>
                  )}
                  {data.ctx_switches_per_sec != null && (
                    <div className="text-xs text-[#8b949e]">
                      Context Switches: {data.ctx_switches_per_sec.toFixed(0)}/s
                    </div>
                  )}

                  {/* CPU Time Breakdown */}
                  {data.cpu_time_breakdown && (
                    <div className="space-y-1">
                      <h4 className="text-xs font-semibold text-[#06b6d4]">CPU Time Breakdown</h4>
                      {Object.entries(data.cpu_time_breakdown).map(([key, val]) => (
                        <div key={key} className="flex items-center gap-2">
                          <span className="text-xs text-[#8b949e] w-16">{key}</span>
                          <ColoredBar value={val} showLabel />
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Load averages */}
                  {data.load_avg && (
                    <div className="text-xs text-[#8b949e]">
                      Load: {data.load_avg['1min'].toFixed(2)} / {data.load_avg['5min'].toFixed(2)} / {data.load_avg['15min'].toFixed(2)}
                    </div>
                  )}

                  {data.uptime_seconds != null && (
                    <div className="text-xs text-[#8b949e]">
                      Uptime: {Math.floor(data.uptime_seconds / 86400)}d{' '}
                      {Math.floor((data.uptime_seconds % 86400) / 3600)}h{' '}
                      {Math.floor((data.uptime_seconds % 3600) / 60)}m
                    </div>
                  )}

                  {/* Per-core grid */}
                  {data.per_cpu && data.per_cpu.length > 0 && (
                    <div className="space-y-2">
                      <h4 className="text-xs font-semibold text-[#06b6d4]">Per-Core Utilization</h4>
                      <div className="flex items-end gap-0.5 h-32">
                        {data.per_cpu.map((pct, i) => (
                          <div key={i} className="flex-1 flex flex-col items-center justify-end h-full">
                            <div
                              className="w-full rounded-t-sm"
                              style={{
                                height: `${Math.max(2, pct)}%`,
                                backgroundColor: `hsl(${(i * 37) % 360}, 60%, 50%)`,
                              }}
                              title={`Core ${i}: ${pct.toFixed(1)}%`}
                            />
                            <span className="text-[8px] text-[#6e7681] mt-0.5">{i}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* GPU Section */}
              {section === 'gpu' && data.gpu && (
                <div className="space-y-4">
                  <GpuWidget gpu={data.gpu} lastUpdated={null} />
                  {data.gpu.temperature != null && (
                    <div className="text-xs text-[#f97316]">Temperature: {data.gpu.temperature.toFixed(1)}°C</div>
                  )}
                  {data.gpu.power_draw != null && (
                    <div className="text-xs text-[#f59e0b]">Power: {data.gpu.power_draw.toFixed(1)} W</div>
                  )}
                  {data.gpu.sclk_mhz != null && (
                    <div className="text-xs text-[#8b949e]">SCLK: {data.gpu.sclk_mhz} MHz</div>
                  )}
                  {data.gpu.mclk_mhz != null && (
                    <div className="text-xs text-[#8b949e]">MCLK: {data.gpu.mclk_mhz} MHz</div>
                  )}
                </div>
              )}

              {/* Disk Section */}
              {section === 'disk' && (
                <DiskWidget disks={data.disks} lastUpdated={null} />
              )}

              {/* Network Section */}
              {section === 'network' && (
                <NetworkWidget network={data.network} isRemote={false} lastUpdated={null} />
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
