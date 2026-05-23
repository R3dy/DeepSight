import { apiClient } from './client';
import type { ApiResponse, SyslogResponse } from '../types';

export function getSyslogEvents(params?: {
  host?: string;
  facility?: string;
  limit?: number;
}): Promise<ApiResponse<SyslogResponse>> {
  const search = new URLSearchParams();
  if (params?.host) search.set('host', params.host);
  if (params?.facility) search.set('facility', params.facility);
  if (params?.limit) search.set('limit', String(params.limit));
  const qs = search.toString();
  return apiClient.get<SyslogResponse>(`/syslog-events${qs ? `?${qs}` : ''}`);
}
