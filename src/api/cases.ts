import { apiClient } from './client';
import type {
  CaseIncident,
  CaseNote,
  CaseCreateInput,
  CaseUpdateInput,
  CaseListResponse,
  CaseBulkResponse,
  CaseMetrics,
  CaseListParams,
} from '../types';

export function getCases(params?: CaseListParams) {
  const searchParams = new URLSearchParams();
  if (params) {
    if (params.status) searchParams.set('status', params.status);
    if (params.severity) searchParams.set('severity', params.severity);
    if (params.priority) searchParams.set('priority', params.priority);
    if (params.assignee_id !== undefined) searchParams.set('assignee_id', String(params.assignee_id));
    if (params.tags) searchParams.set('tags', params.tags);
    if (params.search) searchParams.set('search', params.search);
    if (params.host) searchParams.set('host', params.host);
    if (params.limit !== undefined) searchParams.set('limit', String(params.limit));
    if (params.offset !== undefined) searchParams.set('offset', String(params.offset));
    if (params.sort_by) searchParams.set('sort_by', params.sort_by);
    if (params.sort_dir) searchParams.set('sort_dir', params.sort_dir);
  }
  const qs = searchParams.toString();
  return apiClient.get<CaseListResponse>(`/v2/cases${qs ? `?${qs}` : ''}`);
}

export function getCase(id: number) {
  return apiClient.get<CaseIncident>(`/v2/cases/${id}`);
}

export function createCase(input: CaseCreateInput) {
  return apiClient.post<CaseIncident>('/v2/cases', input);
}

export function updateCase(id: number, input: CaseUpdateInput) {
  return apiClient.patch<CaseIncident>(`/v2/cases/${id}`, input);
}

export function bulkUpdateCases(ids: number[], input: CaseUpdateInput) {
  return apiClient.patch<CaseBulkResponse>('/v2/cases/bulk', { ids, ...input });
}

export function getCaseNotes(caseId: number) {
  return apiClient.get<CaseNote[]>(`/v2/cases/${caseId}/notes`);
}

export function addCaseNote(caseId: number, content: string) {
  return apiClient.post<CaseNote>(`/v2/cases/${caseId}/notes`, { content });
}

export function assignCase(caseId: number, assigneeId: number | null) {
  return apiClient.post<CaseIncident>(`/v2/cases/${caseId}/assign`, { assignee_id: assigneeId });
}

export function addAlertsToCase(caseId: number, alertIds: number[]) {
  return apiClient.post<CaseIncident>(`/v2/cases/${caseId}/alerts`, { alert_ids: alertIds });
}

export function removeAlertFromCase(caseId: number, alertId: number) {
  return apiClient.delete<CaseIncident>(`/v2/cases/${caseId}/alerts/${alertId}`);
}

export function mergeCases(targetId: number, sourceId: number) {
  return apiClient.post<CaseIncident>(`/v2/cases/${targetId}/merge`, { source_case_id: sourceId });
}

export function getCaseMetrics() {
  return apiClient.get<CaseMetrics>('/v2/cases/metrics');
}
