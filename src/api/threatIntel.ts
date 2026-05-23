import { apiClient } from './client';
import type { ApiResponse, ThreatIntelStatus } from '../types';

export function getThreatIntel(): Promise<ApiResponse<ThreatIntelStatus>> {
  return apiClient.get<ThreatIntelStatus>('/threat-intel');
}
