import { apiClient } from './client';
import type {
  ApiResponse,
  Alert,
  SecuritySummary,
  BeaconingEvent,
  AuthEvent,
  FileEvent,
  SecurityDashboardData,
  AlertStats,
} from '../types';

export function getAlerts(params?: {
  severity?: string;
  acknowledged?: boolean;
}): Promise<ApiResponse<{ alerts: Alert[]; count: number }>> {
  const search = new URLSearchParams();
  if (params?.severity) search.set('severity', params.severity);
  if (params?.acknowledged !== undefined)
    search.set('acknowledged', String(params.acknowledged));
  const qs = search.toString();
  return apiClient.get<{ alerts: Alert[]; count: number }>(
    `/alerts${qs ? `?${qs}` : ''}`
  );
}

export function acknowledgeAlert(
  id: number
): Promise<ApiResponse<{ status: string; id: number }>> {
  return apiClient.post<{ status: string; id: number }>('/alerts/acknowledge', {
    id,
  });
}

export function getBeaconing(): Promise<
  ApiResponse<{ beaconing: BeaconingEvent[] }>
> {
  return apiClient.get<{ beaconing: BeaconingEvent[] }>('/beaconing');
}

export function getAuthEvents(
  eventType?: string
): Promise<ApiResponse<{ events: AuthEvent[] }>> {
  const qs = eventType ? `?type=${encodeURIComponent(eventType)}` : '';
  return apiClient.get<{ events: AuthEvent[] }>(`/auth-events${qs}`);
}

export function getFileEvents(): Promise<
  ApiResponse<{ events: FileEvent[] }>
> {
  return apiClient.get<{ events: FileEvent[] }>('/file-events');
}

export function getSecuritySummary(): Promise<ApiResponse<SecuritySummary>> {
  return apiClient.get<SecuritySummary>('/security-summary');
}

export function getAlertStats(
  hours = 24
): Promise<ApiResponse<AlertStats>> {
  return apiClient.get<AlertStats>(`/alert-stats?hours=${hours}`);
}

export function getSecurityDashboards(
  hours = 24
): Promise<ApiResponse<SecurityDashboardData>> {
  return apiClient.get<SecurityDashboardData>(
    `/security-dashboards?hours=${hours}`
  );
}
