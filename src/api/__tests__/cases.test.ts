import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as casesApi from '../cases';
import { apiClient } from '../client';

// Mock the entire client module
vi.mock('../client', () => ({
  apiClient: {
    get: vi.fn(),
    post: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
  },
}));

describe('cases API', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('getCases', () => {
    it('calls GET with no params', () => {
      casesApi.getCases();
      expect(apiClient.get).toHaveBeenCalledWith('/v2/cases');
    });

    it('calls GET with query params', () => {
      casesApi.getCases({ severity: 'critical', status: 'new', limit: 10, offset: 0 });
      expect(apiClient.get).toHaveBeenCalledWith(
        expect.stringContaining('/v2/cases?')
      );
    });
  });

  describe('getCase', () => {
    it('calls GET with case ID', () => {
      casesApi.getCase(42);
      expect(apiClient.get).toHaveBeenCalledWith('/v2/cases/42');
    });
  });

  describe('createCase', () => {
    it('calls POST with input', () => {
      const input = { title: 'Test Case', severity: 'high' as const };
      casesApi.createCase(input);
      expect(apiClient.post).toHaveBeenCalledWith('/v2/cases', input);
    });
  });

  describe('updateCase', () => {
    it('calls PATCH with case ID and input', () => {
      casesApi.updateCase(42, { status: 'investigating' });
      expect(apiClient.patch).toHaveBeenCalledWith('/v2/cases/42', { status: 'investigating' });
    });
  });

  describe('bulkUpdateCases', () => {
    it('calls PATCH with ids and input', () => {
      casesApi.bulkUpdateCases([1, 2, 3], { status: 'resolved' });
      expect(apiClient.patch).toHaveBeenCalledWith('/v2/cases/bulk', {
        ids: [1, 2, 3],
        status: 'resolved',
      });
    });
  });

  describe('addCaseNote', () => {
    it('calls POST with case ID and content', () => {
      casesApi.addCaseNote(42, 'Important note');
      expect(apiClient.post).toHaveBeenCalledWith('/v2/cases/42/notes', { content: 'Important note' });
    });
  });

  describe('assignCase', () => {
    it('calls POST with case ID and assignee ID', () => {
      casesApi.assignCase(42, 7);
      expect(apiClient.post).toHaveBeenCalledWith('/v2/cases/42/assign', { assignee_id: 7 });
    });

    it('calls POST with null assignee for unassign', () => {
      casesApi.assignCase(42, null);
      expect(apiClient.post).toHaveBeenCalledWith('/v2/cases/42/assign', { assignee_id: null });
    });
  });

  describe('addAlertsToCase', () => {
    it('calls POST with case ID and alert IDs', () => {
      casesApi.addAlertsToCase(42, [1, 2]);
      expect(apiClient.post).toHaveBeenCalledWith('/v2/cases/42/alerts', { alert_ids: [1, 2] });
    });
  });

  describe('removeAlertFromCase', () => {
    it('calls DELETE with case ID and alert ID', () => {
      casesApi.removeAlertFromCase(42, 5);
      expect(apiClient.delete).toHaveBeenCalledWith('/v2/cases/42/alerts/5');
    });
  });

  describe('mergeCases', () => {
    it('calls POST with target and source IDs', () => {
      casesApi.mergeCases(10, 5);
      expect(apiClient.post).toHaveBeenCalledWith('/v2/cases/10/merge', { source_case_id: 5 });
    });
  });

  describe('getCaseMetrics', () => {
    it('calls GET to metrics endpoint', () => {
      casesApi.getCaseMetrics();
      expect(apiClient.get).toHaveBeenCalledWith('/v2/cases/metrics');
    });
  });
});
