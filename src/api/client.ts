import type { ApiResponse, ApiError } from '../types';

const API_BASE = '/api';

let authToken: string | null = null;

function safeGetLs(): Storage | null {
  try {
    if (typeof localStorage !== 'undefined' && localStorage) {
      // Verify it's actually usable
      const test = localStorage.getItem;
      if (typeof test === 'function') return localStorage;
    }
  } catch {
    // localStorage not available
  }
  return null;
}

export function setAuthToken(token: string | null) {
  authToken = token;
  try {
    if (token) {
      safeGetLs()?.setItem('deepsight_token', token);
    } else {
      safeGetLs()?.removeItem('deepsight_token');
    }
  } catch {
    // Ignore storage errors
  }
}

export function getAuthToken(): string | null {
  if (authToken) return authToken;

  try {
    authToken = safeGetLs()?.getItem('deepsight_token') ?? null;
  } catch {
    // Ignore storage errors
  }
  return authToken;
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
  options?: { signal?: AbortSignal }
): Promise<ApiResponse<T>> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  const token = getAuthToken();
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  try {
    const res = await fetch(`${API_BASE}${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
      signal: options?.signal,
    });

    if (res.status === 401) {
      // Session expired
      setAuthToken(null);
      // Dispatch custom event so auth context can redirect to login
      window.dispatchEvent(new CustomEvent('deepsight:auth-expired'));
      return { ok: false, error: 'Session expired', status: 401 };
    }

    const data = await res.json();

    if (!res.ok) {
      const err = data as ApiError;
      return { ok: false, error: err.error || `HTTP ${res.status}`, status: res.status };
    }

    return { ok: true, data: data as T };
  } catch (err) {
    if (err instanceof DOMException && err.name === 'AbortError') {
      throw err;
    }
    const message = err instanceof Error ? err.message : 'Network error';
    return { ok: false, error: message, status: 0 };
  }
}

export const apiClient = {
  get: <T>(path: string, options?: { signal?: AbortSignal }) =>
    request<T>('GET', path, undefined, options),
  post: <T>(path: string, body?: unknown, options?: { signal?: AbortSignal }) =>
    request<T>('POST', path, body, options),
  patch: <T>(path: string, body?: unknown, options?: { signal?: AbortSignal }) =>
    request<T>('PATCH', path, body, options),
  delete: <T>(path: string, options?: { signal?: AbortSignal }) =>
    request<T>('DELETE', path, undefined, options),
};
