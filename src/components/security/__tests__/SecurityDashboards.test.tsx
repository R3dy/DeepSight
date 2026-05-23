import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { SecurityDashboards } from '../SecurityDashboards';

// ── Helpers ──
const emptyData = {
  alert_timeline: { labels: [], total: 0 },
  top_source_ips: { labels: [], counts: [], total: 0 },
  mitre_radar: { labels: [], counts: [], total: 0 },
  alert_severity: { labels: [], counts: [], total: 0 },
  agent_health: { labels: [], counts: [], total_hosts: 0, host_names: [] },
  event_distribution: { labels: [], counts: [], total: 0 },
};

const fullData = {
  alert_timeline: {
    labels: ['2026-05-22 12', '2026-05-22 13'],
    critical: [2, 0],
    high: [1, 3],
    medium: [4, 5],
    low: [0, 1],
    info: [1, 2],
    total: 19,
  },
  top_source_ips: {
    labels: ['192.168.1.1', '10.0.0.5'],
    counts: [15, 8],
    total: 23,
  },
  mitre_radar: {
    labels: ['Execution', 'Persistence', 'Discovery'],
    counts: [5, 3, 7],
    total: 15,
  },
  alert_severity: {
    labels: ['critical', 'high', 'medium', 'low', 'info'],
    counts: [2, 4, 9, 1, 3],
    total: 19,
  },
  agent_health: {
    labels: ['Online', 'Stale', 'Offline', 'Unknown'],
    counts: [3, 1, 0, 0],
    total_hosts: 4,
    host_names: ['host-a', 'host-b', 'host-c', 'host-d'],
  },
  event_distribution: {
    labels: ['Alert: brute_force', 'Auth Events', 'File Events'],
    counts: [10, 5, 2],
    total: 17,
  },
};

describe('SecurityDashboards', () => {
  it('renders loading skeletons when isLoading is true', () => {
    render(<SecurityDashboards data={null} isLoading={true} />);
    // Should show 6 skeleton cards
    const skeletons = document.querySelectorAll('.animate-pulse');
    expect(skeletons.length).toBe(6);
  });

  it('renders empty state when data is null and not loading', () => {
    render(<SecurityDashboards data={null} isLoading={false} />);
    expect(screen.getByText('No dashboard data available')).toBeTruthy();
  });

  it('renders all 6 chart panels with full data', () => {
    render(<SecurityDashboards data={fullData} isLoading={false} />);
    expect(screen.getByText('📈 Alert Timeline')).toBeTruthy();
    expect(screen.getByText('🌐 Top Source IPs')).toBeTruthy();
    expect(screen.getByText('🎯 MITRE ATT&CK')).toBeTruthy();
    expect(screen.getByText('🍩 Alert Severity')).toBeTruthy();
    expect(screen.getByText('🤖 Agent Health')).toBeTruthy();
    expect(screen.getByText('📊 Event Distribution')).toBeTruthy();
  });

  it('renders totals correctly from data', () => {
    render(<SecurityDashboards data={fullData} isLoading={false} />);
    // totals appear in badges — use getAllByText since Recharts may duplicate in SVG
    expect(screen.getAllByText('19 alerts').length).toBeGreaterThan(0);
    expect(screen.getAllByText('19 total').length).toBeGreaterThan(0);
    expect(screen.getAllByText('4 hosts').length).toBeGreaterThan(0);
    expect(screen.getAllByText('17 events').length).toBeGreaterThan(0);
  });

  it('renders without crashing when all sub-objects are undefined', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    render(<SecurityDashboards data={{} as any} isLoading={false} />);
    // Should render all 6 panels with empty data messages
    expect(screen.getAllByText('📈 Alert Timeline').length).toBeGreaterThan(0);
    expect(screen.getAllByText('No alert data').length).toBeGreaterThan(0);
    expect(screen.getAllByText('No IP data').length).toBeGreaterThan(0);
    expect(screen.getAllByText('No MITRE data').length).toBeGreaterThan(0);
    expect(screen.getAllByText('No severity data').length).toBeGreaterThan(0);
    expect(screen.getAllByText('No agent data').length).toBeGreaterThan(0);
    expect(screen.getAllByText('No event data').length).toBeGreaterThan(0);
  });

  it('handles mitre_tactics legacy key (backend backward compat)', () => {
    // Backend sends "mitre_tactics", component should map it to mitre_radar
    const legacyData = {
      ...emptyData,
      mitre_radar: undefined as unknown as typeof emptyData.mitre_radar,
    };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const dataWithLegacyKey: any = {
      ...legacyData,
      mitre_tactics: {
        labels: ['Initial Access', 'Execution'],
        counts: [3, 7],
        total: 10,
      },
    };
    render(<SecurityDashboards data={dataWithLegacyKey} isLoading={false} />);
    expect(screen.getAllByText('2 tactics').length).toBeGreaterThan(0);
    // Verify the chart rendered using the fallback
    expect(screen.getAllByText('🎯 MITRE ATT&CK').length).toBeGreaterThan(0);
  });

  it('shows empty state message for each chart when data arrays are empty', () => {
    render(<SecurityDashboards data={emptyData} isLoading={false} />);
    expect(screen.getAllByText('No alert data').length).toBeGreaterThan(0);
    expect(screen.getAllByText('No IP data').length).toBeGreaterThan(0);
    expect(screen.getAllByText('No MITRE data').length).toBeGreaterThan(0);
    expect(screen.getAllByText('No severity data').length).toBeGreaterThan(0);
    expect(screen.getAllByText('No agent data').length).toBeGreaterThan(0);
    expect(screen.getAllByText('No event data').length).toBeGreaterThan(0);
  });

  it('displays 0 alerts badge when total is zero', () => {
    render(<SecurityDashboards data={emptyData} isLoading={false} />);
    expect(screen.getAllByText('0 alerts').length).toBeGreaterThan(0);
  });
});
