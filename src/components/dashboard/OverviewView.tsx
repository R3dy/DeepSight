import { useMemo } from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { ColoredBar } from '../charts/ColoredBar';
import { getColor } from '../charts/colors';
import type { ClusterHost, ProcessInfo } from '../../types';

interface OverviewViewProps {
  clusterData: Record<string, ClusterHost> | null;
  currentHost: string | null;
  isLoading: boolean;
}

function cpuColor(pct: number): string {
  if (pct >= 75) return '#ef4444';
  if (pct >= 50) return '#f97316';
  if (pct >= 25) return '#f59e0b';
  return '#22c55e';
}

function ramColor(pct: number): string {
  if (pct >= 80) return '#ef4444';
  if (pct >= 60) return '#f97316';
  if (pct >= 40) return '#f59e0b';
  return '#22c55e';
}

export function OverviewView({ clusterData, currentHost, isLoading }: OverviewViewProps) {
  const hosts = useMemo(() => {
    if (!clusterData) return [];
    const entries = Object.entries(clusterData).map(([name, info]) => ({
      hostname: name,
      status: info.status,
      memory: info.memory,
      cpu: info.cpu,
      disks: info.disks,
      processes: info.processes,
    }));
    return entries.sort((a, b) => {
      if (a.hostname === currentHost) return -1;
      if (b.hostname === currentHost) return 1;
      return 0;
    });
  }, [clusterData, currentHost]);

  if (isLoading) {
    return (
      <div className="text-center py-8">
        <div className="animate-pulse text-[#8b949e]">Loading cluster data...</div>
      </div>
    );
  }

  if (hosts.length === 0) {
    return (
      <div className="text-center py-12">
        <div className="text-4xl mb-3">📡</div>
        <h3 className="text-lg font-medium text-[#e1e4e8]">No hosts reporting</h3>
        <p className="text-sm text-[#8b949e] mt-1">
          No agents are currently connected. Deploy an agent to get started.
        </p>
      </div>
    );
  }

  // RAM chart data
  const ramChart = hosts.map(h => ({
    name: h.hostname,
    used: h.memory?.used_gb ?? 0,
    cached: h.memory?.cached_gb ?? 0,
    free: h.memory?.free_gb ?? 0,
    pct: h.memory?.percent ?? 0,
  }));

  // CPU chart data
  const cpuChart = hosts.map(h => ({
    name: h.hostname,
    cpu: h.cpu?.percent ?? 0,
  }));

  // Total stats
  const totalRam = hosts.reduce((s, h) => s + (h.memory?.total_gb ?? 0), 0);
  const totalUsed = hosts.reduce((s, h) => s + (h.memory?.used_gb ?? 0), 0);
  const avgCpu = hosts.length > 0
    ? hosts.reduce((s, h) => s + (h.cpu?.percent ?? 0), 0) / hosts.length
    : 0;
  const totalCores = hosts.reduce((s, h) => s + (h.cpu?.count ?? 0), 0);

  // Cross-host top RAM processes
  const allRamProcs: Array<ProcessInfo & { hostname: string }> = [];
  hosts.forEach(h => {
    (h.processes ?? []).forEach(p => {
      allRamProcs.push({ ...p, hostname: h.hostname });
    });
  });
  allRamProcs.sort((a, b) => (b.mem_rss ?? 0) - (a.mem_rss ?? 0));
  const topRamProcs = allRamProcs.slice(0, 12);

  // Cross-host top CPU processes
  const allCpuProcs: Array<ProcessInfo & { hostname: string }> = [];
  hosts.forEach(h => {
    (h.processes ?? []).forEach(p => {
      allCpuProcs.push({ ...p, hostname: h.hostname });
    });
  });
  allCpuProcs.sort((a, b) => (b.cpu_percent ?? 0) - (a.cpu_percent ?? 0));
  const topCpuProcs = allCpuProcs.slice(0, 12);

  return (
    <div className="space-y-4">
      {/* Cluster RAM */}
      <div className="rounded-lg border border-[#30363d] bg-[#161b22] p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold text-[#e1e4e8]">🧠 Cluster Memory</h3>
          <span className="text-xs text-[#8b949e]">
            {hosts.length} hosts · {totalUsed.toFixed(1)} / {totalRam.toFixed(1)} GB
          </span>
        </div>
        <div className="h-[220px]">
          <ResponsiveContainer>
            <BarChart data={ramChart} layout="vertical" margin={{ top: 0, right: 20, left: 100, bottom: 0 }}>
              <XAxis type="number" tick={{ fontSize: 10, fill: '#8b949e' }} />
              <YAxis type="category" dataKey="name" tick={{ fontSize: 10, fill: '#e1e4e8' }} width={95} />
              <Tooltip
                contentStyle={{
                  background: '#161b22',
                  border: '1px solid #30363d',
                  borderRadius: '8px',
                  fontSize: '11px',
                }}
                labelStyle={{ color: '#e1e4e8' }}
              />
              <Bar dataKey="used" stackId="a" fill="#8b5cf6" name="Used">
                {ramChart.map((entry, i) => (
                  <Cell key={i} fill={ramColor(entry.pct)} />
                ))}
              </Bar>
              <Bar dataKey="cached" stackId="a" fill="#f59e0b" name="Cached" />
              <Bar dataKey="free" stackId="a" fill="#1c2129" name="Free" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Cross-Host Top RAM Processes */}
      {topRamProcs.length > 0 && (
        <div className="rounded-lg border border-[#30363d] bg-[#161b22] p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-semibold text-[#e1e4e8]">🔥 Top RAM Consumers — All Hosts</h3>
            <span className="text-xs text-[#8b949e]">12 shown</span>
          </div>
          <div className="max-h-[340px] overflow-y-auto">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-[#161b22]">
                <tr className="text-[#8b949e] border-b border-[#30363d]">
                  <th className="text-left py-1.5 px-2">Host</th>
                  <th className="text-left py-1.5 px-2">Process</th>
                  <th className="text-right py-1.5 px-2">Memory</th>
                  <th className="text-right py-1.5 px-2">%</th>
                </tr>
              </thead>
              <tbody>
                {topRamProcs.map((proc, i) => {
                  const color = getColor(i);
                  const memMb = proc.mem_rss ?? 0;
                  const memGb = memMb / 1024;
                  return (
                    <tr key={i} className="border-b border-[#21262d]">
                      <td className="py-1.5 px-2 text-[#6e7681] font-mono text-[10px] truncate max-w-[100px]">
                        {proc.hostname}
                      </td>
                      <td className="py-1.5 px-2">
                        <div className="flex items-center gap-1.5">
                          <div className="w-1 h-3 rounded-full" style={{ backgroundColor: color }} />
                          <span className="text-[#e1e4e8] truncate max-w-[120px]">{proc.name}</span>
                        </div>
                      </td>
                      <td className="py-1.5 px-2 text-right font-mono text-[#8b949e]">
                        {memGb >= 0.1 ? `${memGb.toFixed(1)} GB` : `${memMb.toFixed(0)} MB`}
                      </td>
                      <td className="py-1.5 px-2 text-right font-mono font-semibold" style={{ color }}>
                        {(proc.mem_percent ?? 0).toFixed(1)}%
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Cluster CPU + Disk side by side */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* CPU */}
        <div className="rounded-lg border border-[#30363d] bg-[#161b22] p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-semibold text-[#e1e4e8]">⚙️ CPU — All Hosts</h3>
            <span className="text-xs text-[#8b949e]">
              {totalCores} cores · avg {avgCpu.toFixed(1)}%
            </span>
          </div>
          <div className="h-[220px]">
            <ResponsiveContainer>
              <BarChart data={cpuChart} layout="vertical" margin={{ top: 0, right: 20, left: 100, bottom: 0 }}>
                <XAxis type="number" domain={[0, 100]} tick={{ fontSize: 10, fill: '#8b949e' }} />
                <YAxis type="category" dataKey="name" tick={{ fontSize: 10, fill: '#e1e4e8' }} width={95} />
                <Tooltip
                  contentStyle={{
                    background: '#161b22',
                    border: '1px solid #30363d',
                    borderRadius: '8px',
                    fontSize: '11px',
                  }}
                />
                <Bar dataKey="cpu" name="CPU %">
                  {cpuChart.map((entry, i) => (
                    <Cell key={i} fill={cpuColor(entry.cpu)} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Disk comparison */}
        <div className="rounded-lg border border-[#30363d] bg-[#161b22] p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-semibold text-[#e1e4e8]">💾 Disk Usage — All Hosts</h3>
            <span className="text-xs text-[#8b949e]">{hosts.length} hosts</span>
          </div>
          <div className="space-y-2 max-h-[220px] overflow-y-auto">
            {hosts.map(host => {
              const rootDisk = host.disks?.find(d => d.mountpoint === '/') ?? host.disks?.[0];
              if (!rootDisk) return null;
              return (
                <div key={host.hostname} className="text-xs">
                  <div className="flex items-center justify-between mb-0.5">
                    <span className="text-[#e1e4e8] font-mono text-[10px]">{host.hostname}</span>
                    <span className="text-[#8b949e] font-mono text-[10px]">
                      {rootDisk.used_gb.toFixed(1)} / {rootDisk.total_gb.toFixed(1)} GB
                    </span>
                  </div>
                  <ColoredBar
                    value={rootDisk.percent}
                    color={
                      rootDisk.percent >= 90 ? '#ef4444'
                      : rootDisk.percent >= 75 ? '#f97316'
                      : rootDisk.percent >= 50 ? '#f59e0b'
                      : '#22c55e'
                    }
                  />
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Cross-Host Top CPU Processes */}
      {topCpuProcs.length > 0 && (
        <div className="rounded-lg border border-[#30363d] bg-[#161b22] p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-semibold text-[#e1e4e8]">⚡ Top CPU Consumers — All Hosts</h3>
            <span className="text-xs text-[#8b949e]">12 shown</span>
          </div>
          <div className="max-h-[340px] overflow-y-auto">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-[#161b22]">
                <tr className="text-[#8b949e] border-b border-[#30363d]">
                  <th className="text-left py-1.5 px-2">Host</th>
                  <th className="text-left py-1.5 px-2">Process</th>
                  <th className="text-right py-1.5 px-2">CPU %</th>
                  <th className="text-right py-1.5 px-2">RAM</th>
                </tr>
              </thead>
              <tbody>
                {topCpuProcs.map((proc, i) => {
                  const color = getColor(i);
                  return (
                    <tr key={i} className="border-b border-[#21262d]">
                      <td className="py-1.5 px-2 text-[#6e7681] font-mono text-[10px] truncate max-w-[100px]">
                        {proc.hostname}
                      </td>
                      <td className="py-1.5 px-2">
                        <div className="flex items-center gap-1.5">
                          <div className="w-1 h-3 rounded-full" style={{ backgroundColor: color }} />
                          <span className="text-[#e1e4e8] truncate max-w-[120px]">{proc.name}</span>
                        </div>
                      </td>
                      <td className="py-1.5 px-2 text-right font-mono font-semibold" style={{ color }}>
                        {(proc.cpu_percent ?? 0).toFixed(1)}%
                      </td>
                      <td className="py-1.5 px-2 text-right font-mono text-[#8b949e]">
                        {(proc.mem_rss ?? 0) > 0
                          ? `${(proc.mem_rss ?? 0).toFixed(0)} MB`
                          : '<1 MB'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
