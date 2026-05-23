import { describe, it, expect, afterEach } from 'vitest';
import { render, screen, fireEvent, cleanup } from '@testing-library/react';
import { CoverageGapAnalysis } from '../CoverageGapAnalysis';
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
  tactics: [],
  gaps: [
    {
      technique_id: 'T1204',
      technique_name: 'User Execution',
      tactic: 'Execution',
      tactic_id: 'TA0002',
      recommendation: 'Monitor process creation events for User Execution patterns.',
    },
    {
      technique_id: 'T1078',
      technique_name: 'Valid Accounts',
      tactic: 'Persistence',
      tactic_id: 'TA0003',
      recommendation: 'Monitor for unusual login patterns: off-hours access, impossible travel, new IPs per user.',
    },
    {
      technique_id: 'T1047',
      technique_name: 'Windows Management Instrumentation',
      tactic: 'Execution',
      tactic_id: 'TA0002',
      recommendation: 'Monitor process creation events for WMI patterns.',
    },
  ],
  overall_coverage_pct: 50,
  total_techniques: 6,
  total_covered: 3,
  total_uncovered: 3,
  generated_at: '2026-05-23T00:00:00Z',
};

describe('CoverageGapAnalysis', () => {
  it('renders loading skeletons when isLoading is true', () => {
    const { container } = render(<CoverageGapAnalysis data={null} isLoading={true} />);
    const skeletons = container.querySelectorAll('.animate-pulse');
    expect(skeletons.length).toBeGreaterThan(0);
  });

  it('renders success state when no gaps exist', () => {
    render(<CoverageGapAnalysis data={emptyData} isLoading={false} />);
    expect(screen.getByText(/No coverage gaps/)).toBeTruthy();
  });

  it('renders gap summary with counts', () => {
    render(<CoverageGapAnalysis data={mockData} isLoading={false} />);
    expect(screen.getByText('Coverage Gap Analysis')).toBeTruthy();
    expect(screen.getByText(/3 uncovered techniques across 2 tactics/)).toBeTruthy();
  });

  it('renders gap cards with technique info', () => {
    render(<CoverageGapAnalysis data={mockData} isLoading={false} />);
    const t1204Elements = screen.getAllByText('T1204');
    expect(t1204Elements.length).toBeGreaterThan(0);
    const userExecElements = screen.getAllByText('User Execution');
    expect(userExecElements.length).toBeGreaterThan(0);
    const t1078Elements = screen.getAllByText('T1078');
    expect(t1078Elements.length).toBeGreaterThan(0);
  });

  it('shows tactic filter buttons with counts', () => {
    render(<CoverageGapAnalysis data={mockData} isLoading={false} />);
    const allBtn = screen.getByText(/^All \(\d+\)/);
    expect(allBtn).toBeTruthy();
    const executionBtn = screen.getByText(/^Execution \(\d+\)/);
    expect(executionBtn).toBeTruthy();
    const persistenceBtn = screen.getByText(/^Persistence \(\d+\)/);
    expect(persistenceBtn).toBeTruthy();
  });

  it('filters gaps by tactic when filter button is clicked', () => {
    render(<CoverageGapAnalysis data={mockData} isLoading={false} />);
    // Initially all 3 gaps visible
    expect(screen.getAllByText('T1204').length).toBeGreaterThan(0);
    expect(screen.getAllByText('T1047').length).toBeGreaterThan(0);

    // Click Execution filter - match the filter button specifically
    const executionBtn = screen.getByText(/^Execution \(\d+\)/);
    fireEvent.click(executionBtn);

    // Only Execution gaps should be visible, T1078 should be hidden
    expect(screen.queryByText('T1078')).toBeNull();
  });

  it('expands gap card to show recommendation on click', () => {
    render(<CoverageGapAnalysis data={mockData} isLoading={false} />);
    // Recommendation should be hidden initially
    expect(screen.queryByText('Recommendation')).toBeNull();

    // Click the first gap card to expand - use the button containing T1204
    const gapButtons = screen.getAllByText('T1204');
    const gapButton = gapButtons[0].closest('button');
    if (gapButton) fireEvent.click(gapButton);

    // Recommendation should now be visible
    expect(screen.getByText('Recommendation')).toBeTruthy();
  });

  it('returns to all gaps when "All" button is clicked', () => {
    render(<CoverageGapAnalysis data={mockData} isLoading={false} />);
    // Filter to Execution
    const executionBtn = screen.getByText(/^Execution \(\d+\)/);
    fireEvent.click(executionBtn);
    expect(screen.queryByText('T1078')).toBeNull();

    // Click All
    const allBtn = screen.getByText(/^All \(\d+\)/);
    fireEvent.click(allBtn);
    expect(screen.queryByText('T1078')).toBeTruthy();
  });
});
