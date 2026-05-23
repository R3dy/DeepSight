import { apiClient } from './client';
import type { HostsResponse, HostStats, ApiResponse } from '../types';

export async function getHosts(): Promise<ApiResponse<HostsResponse>> {
  return apiClient.get<HostsResponse>('/hosts');
}

export async function getHostStats(
  host?: string,
  detail = false
): Promise<ApiResponse<HostStats>> {
  const params = new URLSearchParams();
  if (host) params.set('host', host);
  if (detail) params.set('detail', 'true');
  const qs = params.toString();
  return apiClient.get<HostStats>(`/stats${qs ? `?${qs}` : ''}`);
}

export async function getClusterStats(): Promise<ApiResponse<Record<string, HostStats>>> {
  return apiClient.get<Record<string, HostStats>>('/cluster');
}

export async function getSummary(): Promise<ApiResponse<Record<string, unknown>>> {
  return apiClient.get<Record<string, unknown>>('/summary');
}
