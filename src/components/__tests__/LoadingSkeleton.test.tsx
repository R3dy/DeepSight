import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Skeleton, SkeletonCard, SkeletonTable, PageSkeleton } from '../ui/LoadingSkeleton';

describe('LoadingSkeleton', () => {
  it('renders basic skeleton', () => {
    render(<Skeleton className="h-4 w-10" />);
    const el = screen.getByRole('status');
    expect(el).toBeTruthy();
    expect(el.className).toContain('animate-pulse');
  });

  it('renders skeleton card', () => {
    const { container } = render(<SkeletonCard />);
    expect(container.querySelector('.animate-pulse')).toBeTruthy();
  });

  it('renders skeleton table with correct rows', () => {
    const { container } = render(<SkeletonTable rows={3} />);
    const rows = container.querySelectorAll('.divide-y > div');
    expect(rows.length).toBe(3);
  });

  it('renders page skeleton', () => {
    const { container } = render(<PageSkeleton />);
    // PageSkeleton contains multiple status roles; verify structure exists
    const statuses = container.querySelectorAll('[role="status"]');
    expect(statuses.length).toBeGreaterThan(0);
  });
});
