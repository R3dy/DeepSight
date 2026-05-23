import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { AuthEventsList } from '../AuthEventsList';
import type { AuthEvent } from '../../../types';

const mockEvents: AuthEvent[] = [
  {
    timestamp: '2026-05-23T04:00:00Z',
    event_type: 'failed_password',
    username: 'root',
    source_ip: '192.168.1.100',
    detail: 'Failed password for root from 192.168.1.100 port 22 ssh2',
    failure_count: 3,
  },
  {
    timestamp: '2026-05-23T03:55:00Z',
    event_type: 'accepted_password',
    username: 'admin',
    source_ip: '10.0.0.5',
    detail: 'Accepted password for admin from 10.0.0.5 port 22 ssh2',
  },
];

describe('AuthEventsList', () => {
  it('renders loading skeletons when loading', () => {
    render(<AuthEventsList events={[]} isLoading={true} />);
    const skeletons = document.querySelectorAll('.animate-pulse');
    expect(skeletons.length).toBeGreaterThan(0);
  });

  it('shows empty state when no events', () => {
    render(<AuthEventsList events={[]} isLoading={false} />);
    expect(screen.getByText('No recent auth events')).toBeTruthy();
  });

  it('renders auth events correctly', () => {
    render(<AuthEventsList events={mockEvents} isLoading={false} />);
    expect(screen.getByText('root')).toBeTruthy();
    expect(screen.getByText('admin')).toBeTruthy();
  });

  it('handles event with undefined detail gracefully', () => {
    const eventsWithMissingDetail: AuthEvent[] = [
      {
        timestamp: '2026-05-23T04:00:00Z',
        event_type: 'test_event',
        username: 'test',
        source_ip: '1.2.3.4',
        // detail is deliberately omitted
        detail: undefined as unknown as string,
      },
    ];
    // Should not throw
    expect(() => {
      render(<AuthEventsList events={eventsWithMissingDetail} isLoading={false} />);
    }).not.toThrow();
  });
});
