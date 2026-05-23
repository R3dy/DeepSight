import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from '../context/AuthContext';
import { Login } from '../views/Login';
import { NotFound } from '../views/NotFound';

// Mock the API client
vi.mock('../api/client', () => ({
  setAuthToken: vi.fn(),
  getAuthToken: () => null,
  apiClient: {
    get: vi.fn().mockResolvedValue({ ok: false, error: 'Unauthorized', status: 401 }),
    post: vi.fn().mockResolvedValue({ ok: false, error: 'Unauthorized', status: 401 }),
    patch: vi.fn(),
    delete: vi.fn(),
  },
}));

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: false } },
});

function renderWithProviders(ui: React.ReactElement, { initialEntries = ['/'] } = {}) {
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={initialEntries}>
        <AuthProvider>
          {ui}
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

describe('Auth flow', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('shows login form when unauthenticated', async () => {
    renderWithProviders(<Login />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /sign in/i })).toBeTruthy();
    });
    expect(screen.getByLabelText('Username')).toBeTruthy();
    expect(screen.getByLabelText('Password')).toBeTruthy();
  });
});

describe('NotFound', () => {
  it('shows 404 page', () => {
    renderWithProviders(<NotFound />);
    expect(screen.getByText(/404/)).toBeTruthy();
    expect(screen.getByText(/Page Not Found/)).toBeTruthy();
  });
});
