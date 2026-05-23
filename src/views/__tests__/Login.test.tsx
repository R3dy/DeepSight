import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { Login } from '../Login';

// Hoisted mock values (accessible inside vi.mock factory)
const mockAuth = vi.hoisted(() => ({
  user: null as { id: number; username: string; is_admin: boolean } | null,
  isLoading: false,
  isAuthenticated: false,
  error: null as string | null,
}));

const mockLoginFn = vi.fn();
const mockClearErrorFn = vi.fn();

vi.mock('../../context/AuthContext', () => ({
  useAuth: () => ({
    user: mockAuth.user,
    isLoading: mockAuth.isLoading,
    isAuthenticated: mockAuth.isAuthenticated,
    error: mockAuth.error,
    login: mockLoginFn,
    logout: vi.fn(),
    clearError: mockClearErrorFn,
  }),
}));

function renderLogin() {
  return render(
    <MemoryRouter>
      <Login />
    </MemoryRouter>
  );
}

function resetAuthMock() {
  mockAuth.user = null;
  mockAuth.isLoading = false;
  mockAuth.isAuthenticated = false;
  mockAuth.error = null;
}

describe('Login', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetAuthMock();
  });

  it('renders login form', () => {
    renderLogin();
    // Both heading and button say "Sign In", so use role-based queries
    expect(screen.getByRole('heading', { name: /sign in/i })).toBeTruthy();
    expect(screen.getByLabelText('Username')).toBeTruthy();
    expect(screen.getByLabelText('Password')).toBeTruthy();
  });

  it('calls login on form submit', async () => {
    renderLogin();

    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'admin' } });
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'password123' } });

    mockLoginFn.mockResolvedValueOnce(true);

    fireEvent.submit(screen.getByRole('button', { name: /sign in/i }));

    await waitFor(() => {
      expect(mockLoginFn).toHaveBeenCalledWith({
        username: 'admin',
        password: 'password123',
      });
    });
  });

  it('disables submit button while loading', () => {
    mockAuth.isLoading = true;
    renderLogin();
    const button = screen.getByRole('button');
    expect(button.textContent).toBe('Signing in...');
  });

  it('shows error message', () => {
    mockAuth.error = 'Invalid credentials';
    renderLogin();
    expect(screen.getByText('Invalid credentials')).toBeTruthy();
  });

  it('disables button when fields are empty', () => {
    renderLogin();
    const button = screen.getByRole('button', { name: /sign in/i });
    expect(button).toBeDisabled();
  });

  it('clears error on input change', () => {
    mockAuth.error = 'Invalid credentials';
    renderLogin();
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'a' } });
    expect(mockClearErrorFn).toHaveBeenCalled();
  });
});
