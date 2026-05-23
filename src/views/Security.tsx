import { useState, useCallback, useEffect } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  getAlerts, acknowledgeAlert, getBeaconing, getAuthEvents, getFileEvents,
  getSecuritySummary, getSecurityDashboards, getAttackCoverage,
} from '../api';
import { getThreatIntel } from '../api/threatIntel';
import { getSyslogEvents } from '../api/syslog';
import {
  AlertSummaryBar, AlertList, BeaconingList, AuthEventsList,
  FileIntegrityTable, SecurityDashboards, ThreatIntelGrid,
  SyslogViewer, SearchInterface, AttackCoverageHeatmap,
  CoverageGapAnalysis, PlaybookHistory,
} from '../components/security';
import type { Alert } from '../types';

type SecTab = 'overview' | 'search' | 'syslog' | 'attack' | 'playbooks';

export function Security() {
  const queryClient = useQueryClient();
  const [tab, setTab] = useState<SecTab>('overview');
  const [acknowledgedIds, setAcknowledgedIds] = useState<Set<number>>(new Set());
  const [paused, setPaused] = useState(false);

  // Syslog filters
  const [syslogHost, setSyslogHost] = useState<string | undefined>();
  const [syslogFacility, setSyslogFacility] = useState<string | undefined>();

  // ── Alerts ──
  const { data: alertsResult, isLoading: alertsLoading } = useQuery({
    queryKey: ['alerts'],
    queryFn: () => getAlerts(),
    refetchInterval: paused ? false : 5000,
    staleTime: 3000,
    enabled: tab === 'overview',
  });
  const alertData = alertsResult?.ok ? alertsResult.data : null;
  const alerts: Alert[] = alertData?.alerts ?? [];

  // ── Security Summary ──
  const { data: summaryResult, isLoading: summaryLoading } = useQuery({
    queryKey: ['securitySummary'],
    queryFn: getSecuritySummary,
    refetchInterval: paused ? false : 5000,
    staleTime: 3000,
    enabled: tab === 'overview',
  });
  const summary = summaryResult?.ok ? summaryResult.data : null;

  // ── Beaconing ──
  const { data: beaconingResult, isLoading: beaconingLoading } = useQuery({
    queryKey: ['beaconing'],
    queryFn: getBeaconing,
    refetchInterval: paused ? false : 10000,
    staleTime: 5000,
    enabled: tab === 'overview',
  });
  const beaconing = beaconingResult?.ok ? beaconingResult.data.beaconing : [];

  // ── Auth Events ──
  const { data: authResult, isLoading: authLoading } = useQuery({
    queryKey: ['authEvents'],
    queryFn: () => getAuthEvents(),
    refetchInterval: paused ? false : 10000,
    staleTime: 5000,
    enabled: tab === 'overview',
  });
  const authEvents = authResult?.ok ? authResult.data.events : [];

  // ── File Events ──
  const { data: fileResult, isLoading: fileLoading } = useQuery({
    queryKey: ['fileEvents'],
    queryFn: getFileEvents,
    refetchInterval: paused ? false : 10000,
    staleTime: 5000,
    enabled: tab === 'overview',
  });
  const fileEvents = fileResult?.ok ? fileResult.data.events : [];

  // ── Security Dashboards ──
  const { data: dashboardsResult, isLoading: dashboardsLoading } = useQuery({
    queryKey: ['securityDashboards'],
    queryFn: () => getSecurityDashboards(),
    refetchInterval: paused ? false : 30000,
    staleTime: 15000,
    enabled: tab === 'overview',
  });
  const dashboardsData = dashboardsResult?.ok ? dashboardsResult.data : null;

  // ── Threat Intel ──
  const { data: tiResult, isLoading: tiLoading, isError: tiError } = useQuery({
    queryKey: ['threatIntel'],
    queryFn: getThreatIntel,
    refetchInterval: paused ? false : 60000,
    staleTime: 30000,
    enabled: tab === 'overview',
  });
  const tiData = tiResult?.ok ? tiResult.data : null;

  // ── Syslog ──
  const { data: syslogResult, isLoading: syslogLoading } = useQuery({
    queryKey: ['syslog', syslogHost, syslogFacility],
    queryFn: () => getSyslogEvents({ host: syslogHost, facility: syslogFacility }),
    refetchInterval: paused ? false : 10000,
    staleTime: 5000,
    enabled: tab === 'syslog',
  });
  const syslogData = syslogResult?.ok ? syslogResult.data : null;

  // ── ATT&CK Coverage ──
  const { data: coverageResult, isLoading: coverageLoading } = useQuery({
    queryKey: ['attackCoverage'],
    queryFn: getAttackCoverage,
    refetchInterval: paused ? false : 60000,
    staleTime: 30000,
    enabled: tab === 'attack',
  });
  const coverageData = coverageResult?.ok ? coverageResult.data : null;

  // ── Acknowledge ──
  const handleAcknowledge = useCallback(async (id: number) => {
    setAcknowledgedIds(prev => new Set(prev).add(id));
    const result = await acknowledgeAlert(id);
    if (!result.ok) {
      setAcknowledgedIds(prev => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
    } else {
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
      queryClient.invalidateQueries({ queryKey: ['securitySummary'] });
    }
  }, [queryClient]);

  // ── Syslog filter ──
  const handleSyslogFilter = useCallback((host?: string, facility?: string) => {
    setSyslogHost(host);
    setSyslogFacility(facility);
  }, []);

  // ── Stop polling when tab changes ──
  useEffect(() => {
    return () => {
      // Invalidate queries when leaving
      if (tab !== 'overview') {
        queryClient.cancelQueries({ queryKey: ['alerts'] });
        queryClient.cancelQueries({ queryKey: ['securitySummary'] });
        queryClient.cancelQueries({ queryKey: ['beaconing'] });
      }
    };
  }, [tab, queryClient]);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div>
          <h2 className="text-xl font-bold text-[#e1e4e8]">Security</h2>
          <p className="text-sm text-[#8b949e]">SIEM detection &amp; alerting</p>
        </div>
        <div className="flex items-center gap-2">
          {/* Tab navigation */}
          <div className="flex rounded-lg border border-[#30363d] overflow-hidden">
            {([
              { key: 'overview' as const, label: 'Overview', icon: '🛡️' },
              { key: 'attack' as const, label: 'ATT&CK', icon: '🎯' },
              { key: 'playbooks' as const, label: 'Playbooks', icon: '⚡' },
              { key: 'search' as const, label: 'Search', icon: '🔍' },
              { key: 'syslog' as const, label: 'Syslog', icon: '📋' },
            ]).map(t => (
              <button
                key={t.key}
                type="button"
                onClick={() => setTab(t.key)}
                className={`px-3 py-1.5 text-xs font-medium transition-colors ${
                  tab === t.key
                    ? 'bg-[#1c2129] text-[#a78bfa]'
                    : 'text-[#8b949e] hover:text-[#e1e4e8]'
                } ${t.key !== 'overview' ? 'border-l border-[#30363d]' : ''}`}
              >
                {t.icon} {t.label}
              </button>
            ))}
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
        </div>
      </div>

      {/* Overview Tab */}
      {tab === 'overview' && (
        <div className="space-y-4">
          {/* Alert Summary Bar */}
          <AlertSummaryBar summary={summary} isLoading={summaryLoading} />

          {/* Alert List */}
          <div className="rounded-lg border border-[#30363d] bg-[#161b22] p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-[#e1e4e8]">🚨 Active Alerts</h3>
              <span className="text-[10px] text-[#8b949e]">
                {alertData?.count ?? 0} alert{(alertData?.count ?? 0) !== 1 ? 's' : ''}
              </span>
            </div>
            <AlertList
              alerts={alerts}
              isLoading={alertsLoading}
              acknowledgedIds={acknowledgedIds}
              onAcknowledge={handleAcknowledge}
            />
          </div>

          {/* Beaconing + Auth + File Integrity side by side */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="rounded-lg border border-[#30363d] bg-[#161b22] p-4">
              <h3 className="text-sm font-semibold text-[#e1e4e8] mb-3">🔗 Beaconing</h3>
              <BeaconingList beaconing={beaconing} isLoading={beaconingLoading} />
            </div>
            <div className="rounded-lg border border-[#30363d] bg-[#161b22] p-4">
              <h3 className="text-sm font-semibold text-[#e1e4e8] mb-3">🔐 Auth Events</h3>
              <AuthEventsList events={authEvents} isLoading={authLoading} />
            </div>
            <div className="rounded-lg border border-[#30363d] bg-[#161b22] p-4">
              <h3 className="text-sm font-semibold text-[#e1e4e8] mb-3">📁 File Integrity</h3>
              <FileIntegrityTable events={fileEvents} isLoading={fileLoading} />
            </div>
          </div>

          {/* Security Dashboards */}
          <div className="rounded-lg border border-[#30363d] bg-[#161b22] p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-[#e1e4e8]">📊 Security Dashboards</h3>
              <span className="text-[10px] text-[#8b949e]">Updated every 30s</span>
            </div>
            <SecurityDashboards data={dashboardsData} isLoading={dashboardsLoading} />
          </div>

          {/* Threat Intel */}
          <div className="rounded-lg border border-[#30363d] bg-[#161b22] p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-[#e1e4e8]">🌍 Threat Intelligence</h3>
              <span className="text-[10px] text-[#8b949e]">Updated every 60s</span>
            </div>
            <ThreatIntelGrid data={tiData} isLoading={tiLoading} isError={tiError} />
          </div>
        </div>
      )}

      {/* ATT&CK Coverage Tab */}
      {tab === 'attack' && (
        <div className="space-y-4">
          {/* Coverage Heatmap */}
          <div className="rounded-lg border border-[#30363d] bg-[#161b22] p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-[#e1e4e8]">🎯 MITRE ATT&amp;CK Coverage Heatmap</h3>
              <span className="text-[10px] text-[#8b949e]">Updated every 60s</span>
            </div>
            <AttackCoverageHeatmap data={coverageData} isLoading={coverageLoading} />
          </div>

          {/* Gap Analysis */}
          <div className="rounded-lg border border-[#30363d] bg-[#161b22] p-4">
            <CoverageGapAnalysis data={coverageData} isLoading={coverageLoading} />
          </div>
        </div>
      )}

      {/* Search Tab */}
      {tab === 'search' && (
        <div className="rounded-lg border border-[#30363d] bg-[#161b22] p-4">
          <h3 className="text-sm font-semibold text-[#e1e4e8] mb-3">🔍 Advanced Search</h3>
          <p className="text-[10px] text-[#8b949e] mb-3">
            Supports field:value syntax. Fields: category, severity, host, source, type, after, before, limit
          </p>
          <SearchInterface />
        </div>
      )}

{ tab === 'playbooks' && (
        <PlaybookHistory />
      )}

      {/* Syslog Tab */}
      {tab === 'syslog' && (
        <div className="rounded-lg border border-[#30363d] bg-[#161b22] p-4">
          <h3 className="text-sm font-semibold text-[#e1e4e8] mb-3">📋 Syslog Events</h3>
          <SyslogViewer
            events={syslogData?.events ?? []}
            hosts={syslogData?.hosts ?? []}
            facilities={syslogData?.facilities ?? []}
            isLoading={syslogLoading}
            onFilterChange={handleSyslogFilter}
            selectedHost={syslogHost}
            selectedFacility={syslogFacility}
          />
        </div>
      )}
    </div>
  );
}
