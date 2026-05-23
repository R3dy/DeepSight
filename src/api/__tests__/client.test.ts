import { describe, it, expect, vi, afterEach } from 'vitest';
import { apiClient, setAuthToken, getAuthToken } from '../client';

describe('API Client', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    // Reset auth without touching localStorage
    setAuthToken(null);
  });

  describe('token management', () => {
    it('stores and retrieves token in memory', () => {
      setAuthToken('test-token');
      expect(getAuthToken()).toBe('test-token');
    });

    it('clears token from memory', () => {
      setAuthToken('test-token');
      setAuthToken(null);
      expect(getAuthToken()).toBeNull();
    });

    it('stores token in localStorage when available', () => {
      const lsSet = vi.fn();
      const lsRemove = vi.fn();
      const lsGet = vi.fn().mockReturnValue(null);
      vi.stubGlobal('localStorage', {
        getItem: lsGet,
        setItem: lsSet,
        removeItem: lsRemove,
      });

      setAuthToken('stored-token');
      expect(lsSet).toHaveBeenCalledWith('deepsight_token', 'stored-token');
    });

    it('reads token from localStorage on first call', () => {
      const lsGet = vi.fn().mockReturnValue('stored-token');
      vi.stubGlobal('localStorage', {
        getItem: lsGet,
        setItem: vi.fn(),
        removeItem: vi.fn(),
      });

      // Clear cached token, then read from LS
      setAuthToken(null);
      const token = getAuthToken();
      expect(token).toBe('stored-token');
      expect(lsGet).toHaveBeenCalledWith('deepsight_token');
    });
  });

  describe('HTTP methods', () => {
    it('makes GET request with auth header', async () => {
      setAuthToken('test-token');

      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ data: 'test' }),
      });
      vi.stubGlobal('fetch', mockFetch);

      const result = await apiClient.get('/test');
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.data).toEqual({ data: 'test' });
      }

      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('/api/test');
      expect(init.headers['Authorization']).toBe('Bearer test-token');
    });

    it('handles 401 by dispatching auth-expired event', async () => {
      setAuthToken('expired-token');

      const mockFetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 401,
        json: () => Promise.resolve({ error: 'Unauthorized' }),
      });
      vi.stubGlobal('fetch', mockFetch);

      let eventFired = false;
      const handler = () => { eventFired = true; };
      window.addEventListener('deepsight:auth-expired', handler);

      const result = await apiClient.get('/test');
      expect(result.ok).toBe(false);
      expect(eventFired).toBe(true);

      window.removeEventListener('deepsight:auth-expired', handler);
    });

    it('handles network error', async () => {
      const mockFetch = vi.fn().mockRejectedValue(new Error('Network error'));
      vi.stubGlobal('fetch', mockFetch);

      const result = await apiClient.get('/test');
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toBe('Network error');
        expect(result.status).toBe(0);
      }
    });

    it('makes POST request with body', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ id: 1 }),
      });
      vi.stubGlobal('fetch', mockFetch);

      await apiClient.post('/test', { name: 'test' });

      const [, init] = mockFetch.mock.calls[0];
      expect(init.method).toBe('POST');
      expect(init.body).toBe(JSON.stringify({ name: 'test' }));
    });

    it('handles non-ok responses with error message', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        json: () => Promise.resolve({ error: 'Internal Server Error' }),
      });
      vi.stubGlobal('fetch', mockFetch);

      const result = await apiClient.get('/test');
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toBe('Internal Server Error');
        expect(result.status).toBe(500);
      }
    });
  });
});
