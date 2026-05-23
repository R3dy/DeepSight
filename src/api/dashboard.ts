import { apiClient } from './client';
import type {
  ApiResponse,
  DeepDiveData,
  ProcessDetail,
  NetworkStats,
  ClusterData,
} from '../types';

export function getClusterStats(): Promise<ApiResponse<ClusterData>> {
  return apiClient.get<ClusterData>('/cluster');
}

export function getDeepDive(host?: string): Promise<ApiResponse<DeepDiveData>> {
  const params = new URLSearchParams({ detail: 'true' });
  if (host) params.set('host', host);
  return apiClient.get<DeepDiveData>(`/stats?${params.toString()}`);
}

export function getProcessDetail(
  pid: number,
  host?: string
): Promise<ApiResponse<ProcessDetail>> {
  const params = new URLSearchParams();
  if (host) params.set('host', host);
  const qs = params.toString();
  return apiClient.get<ProcessDetail>(
    `/process/${pid}${qs ? `?${qs}` : ''}`
  );
}

export function getNetworkStats(): Promise<ApiResponse<NetworkStats>> {
  return apiClient.get<NetworkStats>('/network');
}

export function getUsers(): Promise<
  ApiResponse<{
    users: Array<{
      username: string;
      terminal: string;
      source_ip: string;
      activity: string;
    }>;
  }>
> {
  return apiClient.get<{
    users: Array<{
      username: string;
      terminal: string;
      source_ip: string;
      activity: string;
    }>;
  }>('/users');
}
