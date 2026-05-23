import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { CaseSeverityBadge } from '../CaseSeverityBadge';

describe('CaseSeverityBadge', () => {
  it('renders "Critical" severity with rose styling', () => {
    render(<CaseSeverityBadge severity="critical" />);
    const badge = screen.getByText('Critical');
    expect(badge).toBeTruthy();
    expect(badge.className).toContain('bg-rose');
  });

  it('renders "High" severity with orange styling', () => {
    render(<CaseSeverityBadge severity="high" />);
    const badge = screen.getByText('High');
    expect(badge).toBeTruthy();
    expect(badge.className).toContain('bg-orange');
  });

  it('renders "Medium" severity with yellow styling', () => {
    render(<CaseSeverityBadge severity="medium" />);
    const badge = screen.getByText('Medium');
    expect(badge).toBeTruthy();
    expect(badge.className).toContain('bg-yellow');
  });

  it('renders "Low" severity with cyan styling', () => {
    render(<CaseSeverityBadge severity="low" />);
    const badge = screen.getByText('Low');
    expect(badge).toBeTruthy();
    expect(badge.className).toContain('bg-cyan');
  });
});
