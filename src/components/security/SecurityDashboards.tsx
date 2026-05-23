import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  BarChart, Bar, PieChart, Pie, Cell, RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
} from 'recharts';
import type { SecurityDashboardData } from '../../types';

interface SecurityDashboardsProps {
  data: SecurityDashboardData | null;
  isLoading: boolean;
}

const SEV_COLORS: Record<string, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#f59e0b',
  low: '#3b82f6',
  info: '#6b7280',
};

const CHART_COLORS = ['#8b5cf6', '#06b6d4', '#10b981', '#f59e0b', '#f97316', '#ef4444', '#ec4899', '#6366f1'];

const TOOLTIP_STYLE = {
  background: '#161b22',
  border: '1px solid #30363d',
  borderRadius: '8px',
  fontSize: '11px',
};

export function SecurityDashboards({ data, isLoading }: SecurityDashboardsProps) {
  if (isLoading) {
    return (
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {Array.from({ length: 6 }).map((_, i) => (
          <div key={i} className="rounded-lg border border-[#30363d] bg-[#161b22] p-4 animate-pulse">
            <div className="h-4 w-32 bg-[#21262d] rounded mb-3" />
            <div className="h-[200px] bg-[#21262d] rounded" />
          </div>
        ))}
      </div>
    );
  }

  if (!data) {
    return (
      <div className="text-center py-8 text-[#8b949e]">
        <div className="text-xl mb-1">📊</div>
        <p className="text-xs">No dashboard data available</p>
      </div>
    );
  }

  // ── Safe defaults: each sub-object defaults to an empty shape when undefined ──
  const safeData = {
    alert_timeline: data.alert_timeline ?? { labels: [], total: 0 },
    top_source_ips: data.top_source_ips ?? { labels: [], counts: [], total: 0 },
    mitre_radar: data.mitre_radar ?? (data as unknown as { mitre_tactics?: SecurityDashboardData['mitre_radar'] }).mitre_tactics ?? { labels: [], counts: [], total: 0 },
    alert_severity: data.alert_severity ?? { labels: [], counts: [], total: 0 },
    agent_health: data.agent_health ?? { labels: [], counts: [], total_hosts: 0, host_names: [] },
    event_distribution: data.event_distribution ?? { labels: [], counts: [], total: 0 },
  };

  // Alert Timeline
  const tl = safeData.alert_timeline;
  const tlSeries = (['critical', 'high', 'medium', 'low', 'info'] as const)
    .filter(sev => tl[sev] && (tl[sev] as number[]).some((v: number) => v > 0))
    .map(sev => ({
      name: sev,
      data: (tl.labels ?? []).map((label: string, i: number) => ({
        time: label,
        count: (tl[sev] as number[])?.[i] ?? 0,
      })),
    }));

  // Top Source IPs
  const ips = safeData.top_source_ips;
  const ipsData = (ips.labels ?? []).map((label: string, i: number) => ({
    name: label.length > 18 ? label.substring(0, 17) + '…' : label,
    count: ips.counts?.[i] ?? 0,
  })).slice(0, 10);

  // MITRE Radar
  const mitre = safeData.mitre_radar;
  const mitreData = (mitre.labels ?? []).map((label: string, i: number) => ({
    tactic: label,
    count: mitre.counts?.[i] ?? 0,
  }));

  // Severity Doughnut
  const sev = safeData.alert_severity;
  const sevData = (sev.labels ?? []).map((label: string, i: number) => ({
    name: label,
    value: sev.counts?.[i] ?? 0,
    color: SEV_COLORS[label.toLowerCase()] ?? CHART_COLORS[i % CHART_COLORS.length],
  }));

  // Agent Health Doughnut
  const ah = safeData.agent_health;
  const ahColorMap: Record<string, string> = {
    Online: '#22c55e',
    Stale: '#f59e0b',
    Offline: '#ef4444',
    Unknown: '#6b7280',
  };
  const ahData = (ah.labels ?? []).map((label: string, i: number) => ({
    name: label,
    value: ah.counts?.[i] ?? 0,
    color: ahColorMap[label] ?? CHART_COLORS[i % CHART_COLORS.length],
  }));

  // Event Type Distribution
  const et = safeData.event_distribution;
  const etData = (et.labels ?? []).map((label: string, i: number) => ({
    name: label,
    count: et.counts?.[i] ?? 0,
    color: CHART_COLORS[i % CHART_COLORS.length],
  }));

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      {/* Alert Timeline */}
      <div className="rounded-lg border border-[#30363d] bg-[#161b22] p-4">
        <div className="flex items-center justify-between mb-3">
          <h4 className="text-xs font-semibold text-[#e1e4e8]">📈 Alert Timeline</h4>
          <span className="text-[10px] text-[#8b949e]">{tl.total} alerts</span>
        </div>
        <div className="h-[200px]">
          {tlSeries.length > 0 ? (
            <ResponsiveContainer>
              <LineChart margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
                <XAxis dataKey="time" tick={{ fontSize: 9, fill: '#6e7681' }} allowDuplicatedCategory={false} />
                <YAxis tick={{ fontSize: 9, fill: '#6e7681' }} allowDecimals={false} />
                <Tooltip contentStyle={TOOLTIP_STYLE} labelStyle={{ color: '#e1e4e8' }} />
                {tlSeries.map(s => (
                  <Line
                    key={s.name}
                    data={s.data}
                    type="monotone"
                    dataKey="count"
                    name={s.name}
                    stroke={SEV_COLORS[s.name] ?? '#6b7280'}
                    strokeWidth={1.5}
                    dot={false}
                  />
                ))}
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-full text-[10px] text-[#6e7681]">
              No alert data
            </div>
          )}
        </div>
      </div>

      {/* Top Source IPs */}
      <div className="rounded-lg border border-[#30363d] bg-[#161b22] p-4">
        <div className="flex items-center justify-between mb-3">
          <h4 className="text-xs font-semibold text-[#e1e4e8]">🌐 Top Source IPs</h4>
          <span className="text-[10px] text-[#8b949e]">{ipsData.length} IPs</span>
        </div>
        <div className="h-[200px]">
          {ipsData.length > 0 ? (
            <ResponsiveContainer>
              <BarChart data={ipsData} layout="vertical" margin={{ top: 0, right: 10, left: 80, bottom: 0 }}>
                <XAxis type="number" tick={{ fontSize: 9, fill: '#6e7681' }} />
                <YAxis type="category" dataKey="name" tick={{ fontSize: 9, fill: '#e1e4e8' }} width={75} />
                <Tooltip contentStyle={TOOLTIP_STYLE} labelStyle={{ color: '#e1e4e8' }} />
                <Bar dataKey="count" fill="#8b5cf6" radius={[0, 2, 2, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-full text-[10px] text-[#6e7681]">
              No IP data
            </div>
          )}
        </div>
      </div>

      {/* MITRE ATT&CK Radar */}
      <div className="rounded-lg border border-[#30363d] bg-[#161b22] p-4">
        <div className="flex items-center justify-between mb-3">
          <h4 className="text-xs font-semibold text-[#e1e4e8]">🎯 MITRE ATT&CK</h4>
          <span className="text-[10px] text-[#8b949e]">{mitreData.length} tactics</span>
        </div>
        <div className="h-[200px]">
          {mitreData.length > 0 ? (
            <ResponsiveContainer>
              <RadarChart data={mitreData}>
                <PolarGrid stroke="#21262d" />
                <PolarAngleAxis dataKey="tactic" tick={{ fontSize: 8, fill: '#8b949e' }} />
                <PolarRadiusAxis tick={{ fontSize: 8, fill: '#6e7681' }} />
                <Radar dataKey="count" stroke="#8b5cf6" fill="#8b5cf6" fillOpacity={0.2} strokeWidth={1.5} />
              </RadarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-full text-[10px] text-[#6e7681]">
              No MITRE data
            </div>
          )}
        </div>
      </div>

      {/* Alert Severity Doughnut */}
      <div className="rounded-lg border border-[#30363d] bg-[#161b22] p-4">
        <div className="flex items-center justify-between mb-3">
          <h4 className="text-xs font-semibold text-[#e1e4e8]">🍩 Alert Severity</h4>
          <span className="text-[10px] text-[#8b949e]">{sev.total} total</span>
        </div>
        <div className="h-[200px] flex items-center justify-center">
          {sevData.some(d => d.value > 0) ? (
            <ResponsiveContainer width="70%" height="100%">
              <PieChart>
                <Pie
                  data={sevData}
                  cx="50%"
                  cy="50%"
                  innerRadius={45}
                  outerRadius={80}
                  dataKey="value"
                  strokeWidth={0}
                >
                  {sevData.map((d, i) => (
                    <Cell key={i} fill={d.color} />
                  ))}
                </Pie>
                <Tooltip contentStyle={TOOLTIP_STYLE} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="text-[10px] text-[#6e7681]">No severity data</div>
          )}
        </div>
        <div className="flex justify-center gap-3 flex-wrap text-[10px] mt-2">
          {sevData.map((d, i) => (
            <div key={i} className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full" style={{ backgroundColor: d.color }} />
              <span className="text-[#8b949e]">{d.name}</span>
              <span className="text-[#e1e4e8] font-mono">{d.value}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Agent Health Doughnut */}
      <div className="rounded-lg border border-[#30363d] bg-[#161b22] p-4">
        <div className="flex items-center justify-between mb-3">
          <h4 className="text-xs font-semibold text-[#e1e4e8]">🤖 Agent Health</h4>
          <span className="text-[10px] text-[#8b949e]">{ah.total_hosts} hosts</span>
        </div>
        <div className="h-[200px] flex items-center justify-center">
          {ahData.some(d => d.value > 0) ? (
            <ResponsiveContainer width="70%" height="100%">
              <PieChart>
                <Pie
                  data={ahData}
                  cx="50%"
                  cy="50%"
                  innerRadius={45}
                  outerRadius={80}
                  dataKey="value"
                  strokeWidth={0}
                >
                  {ahData.map((d, i) => (
                    <Cell key={i} fill={d.color} />
                  ))}
                </Pie>
                <Tooltip contentStyle={TOOLTIP_STYLE} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="text-[10px] text-[#6e7681]">No agent data</div>
          )}
        </div>
        <div className="flex justify-center gap-3 flex-wrap text-[10px] mt-2">
          {ahData.map((d, i) => (
            <div key={i} className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full" style={{ backgroundColor: d.color }} />
              <span className="text-[#8b949e]">{d.name}</span>
              <span className="text-[#e1e4e8] font-mono">{d.value}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Event Type Distribution */}
      <div className="rounded-lg border border-[#30363d] bg-[#161b22] p-4">
        <div className="flex items-center justify-between mb-3">
          <h4 className="text-xs font-semibold text-[#e1e4e8]">📊 Event Distribution</h4>
          <span className="text-[10px] text-[#8b949e]">{et.total} events</span>
        </div>
        <div className="h-[200px]">
          {etData.length > 0 ? (
            <ResponsiveContainer>
              <BarChart data={etData} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
                <XAxis dataKey="name" tick={{ fontSize: 9, fill: '#6e7681' }} />
                <YAxis tick={{ fontSize: 9, fill: '#6e7681' }} allowDecimals={false} />
                <Tooltip contentStyle={TOOLTIP_STYLE} labelStyle={{ color: '#e1e4e8' }} />
                <Bar dataKey="count" radius={[2, 2, 0, 0]}>
                  {etData.map((d, i) => (
                    <Cell key={i} fill={d.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-full text-[10px] text-[#6e7681]">
              No event data
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
