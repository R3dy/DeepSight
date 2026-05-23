import { apiClient } from './client';
import type { ApiResponse, SearchResponse } from '../types';

export function searchEvents(
  query: string
): Promise<ApiResponse<SearchResponse>> {
  return apiClient.get<SearchResponse>(
    `/search?q=${encodeURIComponent(query)}`
  );
}
