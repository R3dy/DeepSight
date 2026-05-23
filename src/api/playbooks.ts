/**
 * Playbook API — SOAR enrichment playbooks.
 */

import { apiClient } from './client';

// ── Types ──

export interface PlaybookInfo {
  name: string;
  description: string;
}

export interface PlaybookRunSummary {
  name: string;
  status: 'success' | 'partial' | 'error' | 'running';
}

export interface PlaybookHistoryEntry {
  alert_id: number;
  timestamp: string;
  playbooks_run: PlaybookRunSummary[];
}

export interface PlaybookHistoryData {
  history: PlaybookHistoryEntry[];
  total: number;
  limit: number;
  offset: number;
}

export interface EnrichmentStepResult {
  name: string;
  status: 'success' | 'error' | 'pending';
  data: Record<string, unknown> | null;
  error: string | null;
  duration_ms: number;
}

export interface PlaybookResult {
  playbook: string;
  alert_id: number;
  started_at: string;
  completed_at?: string;
  status: 'success' | 'partial' | 'error' | 'running';
  steps: EnrichmentStepResult[];
  error: string | null;
}

export interface EnrichmentData {
  alert_id: number;
  enriched_at: string;
  playbook_results: PlaybookResult[];
}

export interface RunPlaybookRequest {
  alert_id?: number;
  playbook: string;
  context?: {
    source_ip?: string;
    source_host?: string;
    category?: string;
    severity?: string;
    title?: string;
    description?: string;
    ips?: string[];
    domains?: string[];
    hashes?: string[];
    extra?: Record<string, unknown>;
  };
}

// ── API Functions ──

/** List all available playbooks. */
export async function getPlaybooks() {
  return apiClient.get<{ data: PlaybookInfo[]; total: number }>('/v2/playbooks');
}

/** Get enrichment results for a specific alert. */
export async function getPlaybookStatus(alertId: number) {
  return apiClient.get<{ data: EnrichmentData }>(`/v2/playbooks/status/${alertId}`);
}

/** Get recent playbook run history (paginated). */
export async function getPlaybookHistory(limit = 50, offset = 0) {
  return apiClient.get<{ data: PlaybookHistoryData }>(
    `/v2/playbooks/history?limit=${limit}&offset=${offset}`
  );
}

/** Manually trigger a playbook enrichment run. */
export async function runPlaybook(req: RunPlaybookRequest) {
  return apiClient.post<{ data: PlaybookResult }>('/v2/playbooks/run', req);
}
