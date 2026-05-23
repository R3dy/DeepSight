import { apiClient } from './client';
import type { ApiResponse, AttackCoverageData } from '../types';

export function getAttackCoverage(): Promise<ApiResponse<AttackCoverageData>> {
  return apiClient.get<AttackCoverageData>('/attack-coverage');
}
