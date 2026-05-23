import { describe, it, expect, afterEach } from 'vitest';
import { render, screen, fireEvent, cleanup } from '@testing-library/react';
import { AttackCoverageHeatmap } from '../AttackCoverageHeatmap';
import type { AttackCoverageData } from '../../../types';

afterEach(() => {
  cleanup();
});

const emptyData: AttackCoverageData = {
  tactics: [],
  gaps: [],
  overall_coverage_pct: 0,
  total_techniques: 0,
  total_covered: 0,
  total_uncovered: 0,
  generated_at: '2026-05-23T00:00:00Z',
};

const mockData: AttackCoverageData = {
  tactics: [
    {
      tactic: 'Execution',
      tactic_id: 'TA0002',
      techniques: [
        { id: 'T1059', name: 'Command and Scripting Interpreter', covered: true, rules: ['Reverse Shell Detection', 'Sigma: Suspicious PowerShell'] },
        { id: 'T1204', name: 'User Execution', covered: false, rules: [] },
        { id: 'T1047', name: 'Windows Management Instrumentation', covered: false, rules: [] },
      ],
      technique_count: 3,
      covered_count: 1,
      uncovered_count: 2,
      coverage_pct: 33.3,
    },
    {
      tactic: 'Persistence',
      tactic_id: 'TA0003',
      techniques: [
        { id: 'T1505', name: 'Server Software Component', covered: true, rules: ['Webshell Detection'] },
        { id: 'T1078', name: 'Valid Accounts', covered: false, rules: [] },
      ],
      technique_count: 2,
      covered_count: 1,
      uncovered_count: 1,
      coverage_pct: 50.0,
    },
  ],
  gaps: [
    {
      technique_id: 'T1204',
      technique_name: 'User Execution',
      tactic: 'Execution',
      tactic_id: 'TA0002',
      recommendation: 'Monitor process creation events for User Execution patterns.',
    },
  ],
  overall_coverage_pct: 40.0,
  total_techniques: 5,
  total_covered: 2,
  total_uncovered: 3,
  generated_at: '2026-05-23T00:00:00Z',
};

describe('AttackCoverageHeatmap', () => {
  it('renders loading skeletons when isLoading is true', () => {
    const { container } = render(<AttackCoverageHeatmap data={null} isLoading={true} />);
    const skeletons = container.querySelectorAll('.animate-pulse');
    expect(skeletons.length).toBeGreaterThan(0);
  });

  it('renders empty state when data is null and not loading', () => {
    render(<AttackCoverageHeatmap data={null} isLoading={false} />);
    expect(screen.getByText(/No ATT&CK coverage data available/)).toBeTruthy();
  });

  it('renders empty state when tactics array is empty', () => {
    render(<AttackCoverageHeatmap data={emptyData} isLoading={false} />);
    expect(screen.getByText(/No ATT&CK coverage data available/)).toBeTruthy();
  });

  it('renders overall coverage summary with percentage', () => {
    render(<AttackCoverageHeatmap data={mockData} isLoading={false} />);
    expect(screen.getByText('ATT&CK Coverage Summary')).toBeTruthy();
    expect(screen.getByText('40%')).toBeTruthy();
    expect(screen.getByText('overall coverage')).toBeTruthy();
    expect(screen.getByText(/2 of 5 techniques covered across 2 tactics/)).toBeTruthy();
  });

  it('renders legend with covered and uncovered labels', () => {
    render(<AttackCoverageHeatmap data={mockData} isLoading={false} />);
    expect(screen.getByText('Covered')).toBeTruthy();
    expect(screen.getByText('Uncovered')).toBeTruthy();
  });

  it('renders tactic cards with correct data', () => {
    render(<AttackCoverageHeatmap data={mockData} isLoading={false} />);
    // Tactic names should appear
    const executionEls = screen.getAllByText('Execution');
    expect(executionEls.length).toBeGreaterThan(0);
    const persistenceEls = screen.getAllByText('Persistence');
    expect(persistenceEls.length).toBeGreaterThan(0);
  });

  it('renders technique buttons with correct colors', () => {
    render(<AttackCoverageHeatmap data={mockData} isLoading={false} />);
    // Covered technique T1059 should have green styling
    const t1059 = screen.getByText('T1059');
    expect(t1059.className).toContain('22c55e');
    // Uncovered technique T1204 should have red styling
    const t1204 = screen.getByText('T1204');
    expect(t1204.className).toContain('ef4444');
  });

  it('shows technique detail panel on click (covered technique)', () => {
    render(<AttackCoverageHeatmap data={mockData} isLoading={false} />);
    // Click a covered technique
    const t1059 = screen.getByText('T1059');
    fireEvent.click(t1059);
    // Detail panel should appear
    expect(screen.getByText(/T1059: Command and Scripting Interpreter/)).toBeTruthy();
    expect(screen.getByText('✓ Covered')).toBeTruthy();
    expect(screen.getByText('Detection Rules')).toBeTruthy();
    expect(screen.getByText('Reverse Shell Detection')).toBeTruthy();
  });

  it('shows uncovered detail with suggestion on click', () => {
    render(<AttackCoverageHeatmap data={mockData} isLoading={false} />);
    // Click an uncovered technique
    const t1204 = screen.getByText('T1204');
    fireEvent.click(t1204);
    // Detail panel should show uncovered state
    expect(screen.getByText('✗ Uncovered')).toBeTruthy();
    expect(screen.getByText(/No detection rules currently cover this technique/)).toBeTruthy();
  });

  it('closes detail panel on close button click', () => {
    render(<AttackCoverageHeatmap data={mockData} isLoading={false} />);
    // Open detail
    const t1059 = screen.getByText('T1059');
    fireEvent.click(t1059);
    expect(screen.getByText('✓ Covered')).toBeTruthy();
    // Close detail
    const closeBtn = screen.getByText('✕');
    fireEvent.click(closeBtn);
    // Detail should be gone
    expect(screen.queryByText('✓ Covered')).toBeNull();
  });
});
