/* eslint-disable react-refresh/only-export-components */
import {
  createContext,
  useContext,
  useState,
  useCallback,
  useEffect,
  type ReactNode,
} from 'react';
import { getAuthToken, setAuthToken, login as apiLogin, logout as apiLogout, getAuthStatus } from '../api';
import type { User, LoginRequest } from '../types';

interface AuthState {
  user: User | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  error: string | null;
}

interface AuthContextValue extends AuthState {
  login: (credentials: LoginRequest) => Promise<boolean>;
  logout: () => Promise<void>;
  clearError: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({
    user: null,
    isLoading: !!getAuthToken(), // immediately know we have a token to check
    isAuthenticated: false,
    error: null,
  });

  // Verify existing token on mount
  useEffect(() => {
    const token = getAuthToken();
    if (!token) {
      // eslint-disable-next-line react-hooks/set-state-in-effect -- initial auth state resolution
      setState(prev => {
        if (!prev.isLoading) return prev;
        return { ...prev, isLoading: false };
      });
      return;
    }

    let cancelled = false;
    getAuthStatus().then(result => {
      if (cancelled) return;
      if (result.ok) {
        setState({
          user: result.data.user,
          isLoading: false,
          isAuthenticated: true,
          error: null,
        });
      } else {
        setAuthToken(null);
        setState({
          user: null,
          isLoading: false,
          isAuthenticated: false,
          error: null,
        });
      }
    });

    return () => { cancelled = true; };
  }, []);

  // Listen for auth-expired events from API client
  useEffect(() => {
    const handleExpired = () => {
      setState({
        user: null,
        isLoading: false,
        isAuthenticated: false,
        error: 'Your session has expired. Please log in again.',
      });
    };
    window.addEventListener('deepsight:auth-expired', handleExpired);
    return () => window.removeEventListener('deepsight:auth-expired', handleExpired);
  }, []);

  const login = useCallback(async (credentials: LoginRequest): Promise<boolean> => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));

    const result = await apiLogin(credentials);

    if (result.ok) {
      setAuthToken(result.data.token);
      setState({
        user: result.data.user,
        isLoading: false,
        isAuthenticated: true,
        error: null,
      });
      return true;
    }

    setState(prev => ({
      ...prev,
      isLoading: false,
      isAuthenticated: false,
      error: result.error,
    }));
    return false;
  }, []);

  const logout = useCallback(async () => {
    await apiLogout();
    setAuthToken(null);
    setState({
      user: null,
      isLoading: false,
      isAuthenticated: false,
      error: null,
    });
  }, []);

  const clearError = useCallback(() => {
    setState(prev => ({ ...prev, error: null }));
  }, []);

  return (
    <AuthContext.Provider value={{ ...state, login, logout, clearError }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return ctx;
}
