import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { CaseStatusBadge, getValidTransitions } from '../CaseStatusBadge';

describe('CaseStatusBadge', () => {
  it('renders "New" status with blue styling', () => {
    render(<CaseStatusBadge status="new" />);
    const badge = screen.getByText('New');
    expect(badge).toBeTruthy();
    expect(badge.className).toContain('bg-blue');
  });

  it('renders "Investigating" status with amber styling', () => {
    render(<CaseStatusBadge status="investigating" />);
    const badge = screen.getByText('Investigating');
    expect(badge).toBeTruthy();
    expect(badge.className).toContain('bg-amber');
  });

  it('renders "Escalated" status with rose styling', () => {
    render(<CaseStatusBadge status="escalated" />);
    const badge = screen.getByText('Escalated');
    expect(badge).toBeTruthy();
    expect(badge.className).toContain('bg-rose');
  });

  it('renders "Resolved" status with emerald styling', () => {
    render(<CaseStatusBadge status="resolved" />);
    const badge = screen.getByText('Resolved');
    expect(badge).toBeTruthy();
    expect(badge.className).toContain('bg-emerald');
  });

  it('renders "Closed" status with slate styling', () => {
    render(<CaseStatusBadge status="closed" />);
    const badge = screen.getByText('Closed');
    expect(badge).toBeTruthy();
    expect(badge.className).toContain('bg-slate');
  });
});

describe('getValidTransitions', () => {
  it('returns correct transitions for "new"', () => {
    const transitions = getValidTransitions('new');
    expect(transitions).toContain('investigating');
    expect(transitions).toContain('escalated');
    expect(transitions).toContain('resolved');
    expect(transitions).toContain('closed');
    expect(transitions).toHaveLength(4);
  });

  it('returns correct transitions for "investigating"', () => {
    const transitions = getValidTransitions('investigating');
    expect(transitions).toContain('escalated');
    expect(transitions).toContain('resolved');
    expect(transitions).toContain('closed');
    expect(transitions).toHaveLength(3);
  });

  it('returns correct transitions for "resolved" (can close or reopen)', () => {
    const transitions = getValidTransitions('resolved');
    expect(transitions).toContain('closed');
    expect(transitions).toContain('investigating');
    expect(transitions).toHaveLength(2);
  });

  it('returns correct transitions for "closed" (can only reopen)', () => {
    const transitions = getValidTransitions('closed');
    expect(transitions).toContain('investigating');
    expect(transitions).toHaveLength(1);
  });
});
