import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Sidebar } from '../layout/Sidebar';

// Mock contexts
vi.mock('../../context/AuthContext', () => ({
  useAuth: () => ({
    user: { id: 1, username: 'testuser', is_admin: false },
    isLoading: false,
    isAuthenticated: true,
    error: null,
    login: vi.fn(),
    logout: vi.fn(),
    clearError: vi.fn(),
  }),
}));

vi.mock('../../context/WebSocketContext', () => ({
  useWebSocket: () => ({
    socket: null,
    status: 'connected',
    lastEvent: null,
    reconnectAttempt: 0,
  }),
}));

const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });

function renderSidebar() {
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={['/dashboard']}>
        <Sidebar />
      </MemoryRouter>
    </QueryClientProvider>
  );
}

describe('Sidebar', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders navigation items', () => {
    renderSidebar();
    expect(screen.getByText('Dashboard')).toBeTruthy();
    expect(screen.getByText('Security')).toBeTruthy();
    expect(screen.getByText('Investigate')).toBeTruthy();
    expect(screen.getByText('Admin')).toBeTruthy();
  });

  it('renders the app title', () => {
    renderSidebar();
    expect(screen.getByText('DeepSight')).toBeTruthy();
    expect(screen.getByText('Enterprise SIEM')).toBeTruthy();
  });

  it('shows username', () => {
    renderSidebar();
    expect(screen.getByText('testuser')).toBeTruthy();
  });

  it('shows WebSocket connected status', () => {
    renderSidebar();
    expect(screen.getByText('Live')).toBeTruthy();
  });

  it('has logout button', () => {
    renderSidebar();
    expect(screen.getByText('Logout')).toBeTruthy();
  });

  it('highlights active nav item', () => {
    renderSidebar();
    const dashboardLink = screen.getByText('Dashboard').closest('a');
    expect(dashboardLink?.getAttribute('aria-current')).toBe('page');
  });
});
