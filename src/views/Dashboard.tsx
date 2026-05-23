import { useState, useCallback, useEffect, useRef, useMemo } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { getHosts, getHostStats, getUsers, getProcessDetail } from '../api';
import { getClusterStats, getNetworkStats } from '../api/dashboard';
import {
  HostSelector,
  WidgetCard,
  MemoryWidget,
  CpuWidget,
  GpuWidget,
  DiskWidget,
  NetworkWidget,
  UsersWidget,
  ProcessTable,
  ProcessDetailModal,
  DeepDiveModal,
  OverviewView,
} from '../components/dashboard';
import type { ProcessInfo } from '../types';

type DashboardView = 'detail' | 'overview';

export function Dashboard() {
  const queryClient = useQueryClient();
  const [currentHost, setCurrentHost] = useState<string | null>(() => {
    try {
      return localStorage.getItem('deepsight_selected_host') || null;
    } catch { return null; }
  });
  const [view, setView] = useState<DashboardView>('detail');
  const [paused, setPaused] = useState(false);
  const [procTab, setProcTab] = useState<'ram' | 'cpu'>('ram');
  const [procFilter, setProcFilter] = useState('');
  const [showAllProcs, setShowAllProcs] = useState(false);

  // Modals
  const [processDetailPid, setProcessDetailPid] = useState<number | null>(null);
  const [deepDiveSection, setDeepDiveSection] = useState<'ram' | 'cpu' | 'gpu' | 'disk' | 'network' | null>(null);
  const [tooltipPid, setTooltipPid] = useState<number | null>(null);
  const [tooltipHtml, setTooltipHtml] = useState<string | null>(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });
  const tooltipTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const tooltipCache = useRef<Record<string, string>>({});

  // ── Hosts ──
  const { data: hostsResult } = useQuery({
    queryKey: ['hosts'],
    queryFn: getHosts,
    refetchInterval: paused ? false : 15000,
    staleTime: 10000,
  });
  const hosts = useMemo(
    () => hostsResult?.ok ? hostsResult.data.hosts : {},
    [hostsResult]
  );

  // Set initial host if not set
  useEffect(() => {
    if (!currentHost && Object.keys(hosts).length > 0) {
      const first = Object.keys(hosts)[0];
      // eslint-disable-next-line react-hooks/set-state-in-effect -- initial host selection
      setCurrentHost(first);
    }
  }, [hosts, currentHost]);

  // Persist host selection
  useEffect(() => {
    if (currentHost) {
      try { localStorage.setItem('deepsight_selected_host', currentHost); } catch { /* ignore */ }
    }
  }, [currentHost]);

  // ── Stats ──
  const { data: statsResult, dataUpdatedAt: statsUpdated } = useQuery({
    queryKey: ['stats', currentHost],
    queryFn: () => getHostStats(currentHost ?? undefined),
    refetchInterval: paused ? false : 3000,
    staleTime: 2000,
    enabled: view === 'detail' && !!currentHost,
  });
  const stats = statsResult?.ok ? statsResult.data : null;

  // ── Cluster ──
  const { data: clusterResult, isLoading: clusterLoading } = useQuery({
    queryKey: ['cluster'],
    queryFn: getClusterStats,
    refetchInterval: paused ? false : 10000,
    staleTime: 5000,
    enabled: view === 'overview',
  });
  const clusterData = clusterResult?.ok ? clusterResult.data.hosts : null;

  // ── Network (detail view only) ──
  const { data: networkResult } = useQuery({
    queryKey: ['network'],
    queryFn: getNetworkStats,
    refetchInterval: paused ? false : 10000,
    staleTime: 5000,
    enabled: view === 'detail',
  });
  const networkStats = networkResult?.ok ? networkResult.data : null;

  // ── Users (detail view only) ──
  const { data: usersResult } = useQuery({
    queryKey: ['users'],
    queryFn: getUsers,
    refetchInterval: paused ? false : 15000,
    staleTime: 10000,
    enabled: view === 'detail',
  });
  const users = usersResult?.ok ? usersResult.data.users : [];

  // ── Host selection ──
  const handleHostSelect = useCallback((hostname: string) => {
    setCurrentHost(hostname);
    queryClient.invalidateQueries({ queryKey: ['stats', hostname] });
  }, [queryClient]);

  // ── Process tooltip ──
  const handleProcessHover = useCallback((pid: number, e: React.MouseEvent) => {
    if (pid === 0) return;
    const cacheKey = `${currentHost}:${pid}`;
    const cached = tooltipCache.current[cacheKey];
    if (cached) {
      setTooltipHtml(cached);
      setTooltipPos({ x: e.clientX + 16, y: e.clientY - 10 });
      setTooltipPid(pid);
      return;
    }

    if (tooltipTimerRef.current) clearTimeout(tooltipTimerRef.current);
    tooltipTimerRef.current = setTimeout(async () => {
      const result = await getProcessDetail(pid, currentHost ?? undefined);
      if (result.ok && result.data.found) {
        const p = result.data;
        const html = `<div class="text-xs font-bold text-[#e1e4e8] mb-1">${p.name}</div>
          <div class="text-[10px] text-[#8b949e] mb-1">PID ${p.pid} · ${p.user ?? '?'} · ${p.state}</div>
          <div class="grid grid-cols-3 gap-1 text-[10px] mb-1">
            <div><span class="text-[#6e7681]">RSS</span> <span class="text-[#a78bfa]">${p.vm_rss_mb ?? '?'} MB</span></div>
            <div><span class="text-[#6e7681]">Threads</span> <span>${p.threads ?? '?'}</span></div>
            <div><span class="text-[#6e7681]">CPU</span> <span class="text-[#f97316]">${(p.cpu_percent ?? 0).toFixed(1)}%</span></div>
            <div><span class="text-[#6e7681]">FDs</span> <span>${p.fd_count ?? '?'}</span></div>
            <div><span class="text-[#6e7681]">Children</span> <span>${p.child_count ?? '?'}</span></div>
            <div><span class="text-[#6e7681]">Net</span> <span class="text-[#06b6d4]">${(p.network_connections ?? []).length}</span></div>
          </div>
          <div class="text-[10px] text-[#8b949e] truncate max-w-[280px]">${(p.cmdline ?? '').substring(0, 80)}</div>`;
        tooltipCache.current[cacheKey] = html;
        setTooltipHtml(html);
        setTooltipPos({ x: e.clientX + 16, y: e.clientY - 10 });
        setTooltipPid(pid);
      }
    }, 200);
  }, [currentHost]);

  const handleProcessLeave = useCallback(() => {
    if (tooltipTimerRef.current) clearTimeout(tooltipTimerRef.current);
    setTooltipPid(null);
    setTooltipHtml(null);
  }, []);

  // ── Process click ──
  const handleProcessClick = useCallback((pid: number) => {
    if (pid === 0) return;
    setProcessDetailPid(pid);
  }, []);

  // ── Escape handler for modals ──
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        if (processDetailPid != null) setProcessDetailPid(null);
        else if (deepDiveSection != null) setDeepDiveSection(null);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [processDetailPid, deepDiveSection]);

  // ── Uptime display ──
  const uptimeText = stats?.cpu?.uptime_seconds != null
    ? `${Math.floor(stats.cpu.uptime_seconds / 86400)}d ${Math.floor((stats.cpu.uptime_seconds % 86400) / 3600)}h ${Math.floor((stats.cpu.uptime_seconds % 3600) / 60)}m`
    : null;

  // ── Relative time helper ──
  const relativeTime = (ts: number | null) => {
    if (!ts) return null;
    // eslint-disable-next-line react-hooks/purity
    const seconds = Math.floor((Date.now() - ts) / 1000);
    if (seconds < 5) return 'just now';
    if (seconds < 60) return `${seconds}s ago`;
    return `${Math.floor(seconds / 60)}m ago`;
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div>
          <h2 className="text-xl font-bold text-[#e1e4e8]">Dashboard</h2>
          <p className="text-sm text-[#8b949e]">
            System monitoring overview
            {uptimeText && <span className="ml-3">· Uptime: {uptimeText}</span>}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {/* View tabs */}
          <div className="flex rounded-lg border border-[#30363d] overflow-hidden">
            <button
              type="button"
              onClick={() => setView('detail')}
              className={`px-3 py-1.5 text-xs font-medium transition-colors ${
                view === 'detail' ? 'bg-[#1c2129] text-[#a78bfa]' : 'text-[#8b949e] hover:text-[#e1e4e8]'
              }`}
            >
              Detail
            </button>
            <button
              type="button"
              onClick={() => setView('overview')}
              className={`px-3 py-1.5 text-xs font-medium transition-colors border-l border-[#30363d] ${
                view === 'overview' ? 'bg-[#1c2129] text-[#a78bfa]' : 'text-[#8b949e] hover:text-[#e1e4e8]'
              }`}
            >
              Overview
            </button>
          </div>

          {/* Pause/Resume */}
          <button
            type="button"
            onClick={() => setPaused(!paused)}
            className={`px-3 py-1.5 text-xs font-medium rounded-lg border transition-colors ${
              paused
                ? 'border-[#f59e0b] text-[#f59e0b] bg-[#f59e0b]/10'
                : 'border-[#30363d] text-[#8b949e] hover:border-[#a78bfa]'
            }`}
          >
            {paused ? '⏸ Paused' : '⏯ Pause'}
          </button>

          {/* Host selector */}
          <HostSelector
            hosts={hosts}
            currentHost={currentHost}
            onSelect={handleHostSelect}
          />
        </div>
      </div>

      {/* Detail View */}
      {view === 'detail' && (
        <div className="space-y-4">
          {/* Row 1: RAM / CPU / GPU gauges */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <WidgetCard
              title="RAM"
              icon="🧠"
              badge={
                <span className="text-[10px] text-[#6e7681]">
                  {relativeTime(statsUpdated)}
                </span>
              }
              expandAction={() => setDeepDiveSection('ram')}
            >
              {stats ? (
                <MemoryWidget
                  memory={stats.memory}
                  lastUpdated={relativeTime(statsUpdated)}
                />
              ) : (
                <div className="text-center py-4 text-[#8b949e] animate-pulse text-xs">
                  Loading...
                </div>
              )}
            </WidgetCard>

            <WidgetCard
              title="CPU"
              icon="⚙️"
              badge={
                <span className="text-[10px] text-[#6e7681]">
                  {relativeTime(statsUpdated)}
                </span>
              }
              expandAction={() => setDeepDiveSection('cpu')}
            >
              {stats ? (
                <CpuWidget
                  cpu={stats.cpu}
                  lastUpdated={relativeTime(statsUpdated)}
                />
              ) : (
                <div className="text-center py-4 text-[#8b949e] animate-pulse text-xs">
                  Loading...
                </div>
              )}
            </WidgetCard>

            <WidgetCard
              title="GPU"
              icon="🎮"
              badge={
                <span className="text-[10px] text-[#6e7681]">
                  {relativeTime(statsUpdated)}
                </span>
              }
              expandAction={() => setDeepDiveSection('gpu')}
            >
              {stats ? (
                <GpuWidget
                  gpu={stats.gpu}
                  lastUpdated={relativeTime(statsUpdated)}
                />
              ) : (
                <div className="text-center py-4 text-[#8b949e] animate-pulse text-xs">
                  Loading...
                </div>
              )}
            </WidgetCard>
          </div>

          {/* Process Table */}
          <WidgetCard
            title="Processes"
            icon="📋"
            badge={
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={procFilter}
                  onChange={e => setProcFilter(e.target.value)}
                  placeholder="Filter..."
                  className="w-24 px-2 py-0.5 text-[10px] bg-[#0f1117] border border-[#30363d] rounded text-[#e1e4e8] placeholder-[#6e7681] focus:border-[#a78bfa] outline-none"
                />
                <button
                  type="button"
                  onClick={() => setShowAllProcs(!showAllProcs)}
                  className="text-[10px] text-[#6e7681] hover:text-[#a78bfa]"
                >
                  {showAllProcs ? 'Top 15' : 'Show All'}
                </button>
                <span className="text-[10px] text-[#6e7681]">
                  {relativeTime(statsUpdated)}
                </span>
              </div>
            }
          >
            {stats?.processes ? (
              <ProcessTable
                processes={stats.processes as ProcessInfo[]}
                onProcessClick={handleProcessClick}
                onProcessHover={handleProcessHover}
                onProcessLeave={handleProcessLeave}
                tab={procTab}
                onTabChange={setProcTab}
                filterText={procFilter}
                showAll={showAllProcs}
              />
            ) : (
              <div className="text-center py-4 text-[#8b949e] animate-pulse text-xs">
                Loading processes...
              </div>
            )}
          </WidgetCard>

          {/* Row 3: Disk / Network / Users */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <WidgetCard
              title="Disk"
              icon="💾"
              badge={
                <span className="text-[10px] text-[#6e7681]">
                  {relativeTime(statsUpdated)}
                </span>
              }
              expandAction={() => setDeepDiveSection('disk')}
            >
              {stats ? (
                <DiskWidget
                  disks={stats.disks}
                  lastUpdated={relativeTime(statsUpdated)}
                />
              ) : (
                <div className="text-center py-4 text-[#8b949e] animate-pulse text-xs">
                  Loading...
                </div>
              )}
            </WidgetCard>

            <WidgetCard
              title="Network"
              icon="🌐"
              badge={
                <span className="text-[10px] text-[#6e7681]">
                  {relativeTime(statsUpdated)}
                </span>
              }
              expandAction={() => setDeepDiveSection('network')}
            >
              <NetworkWidget
                network={networkStats ?? stats?.network}
                isRemote={!!(currentHost && currentHost !== 'localhost')}
                lastUpdated={relativeTime(statsUpdated)}
              />
            </WidgetCard>

            <WidgetCard
              title="Users"
              icon="👤"
              badge={
                <span className="text-[10px] text-[#6e7681]">
                  {relativeTime(statsUpdated)}
                </span>
              }
            >
              <UsersWidget
                users={users}
                lastUpdated={relativeTime(statsUpdated)}
              />
            </WidgetCard>
          </div>
        </div>
      )}

      {/* Overview View */}
      {view === 'overview' && (
        <OverviewView
          clusterData={clusterData}
          currentHost={currentHost}
          isLoading={clusterLoading}
        />
      )}

      {/* Process Detail Modal */}
      {processDetailPid != null && (
        <ProcessDetailModal
          pid={processDetailPid}
          host={currentHost ?? undefined}
          onClose={() => setProcessDetailPid(null)}
        />
      )}

      {/* Deep Dive Modal */}
      {deepDiveSection != null && (
        <DeepDiveModal
          section={deepDiveSection}
          host={currentHost}
          onClose={() => setDeepDiveSection(null)}
          onProcessClick={handleProcessClick}
          onProcessHover={handleProcessHover}
          onProcessLeave={handleProcessLeave}
        />
      )}

      {/* Process Tooltip */}
      {tooltipPid != null && tooltipHtml && (
        <div
          className="fixed z-[60] pointer-events-none bg-[#161b22] border border-[#30363d] rounded-lg p-2 shadow-xl max-w-[300px]"
          style={{ left: tooltipPos.x, top: tooltipPos.y }}
          dangerouslySetInnerHTML={{ __html: tooltipHtml }}
        />
      )}
    </div>
  );
}
