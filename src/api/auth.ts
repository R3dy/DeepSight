import { apiClient } from './client';
import type { LoginRequest, LoginResponse, AuthStatus, ApiResponse } from '../types';

export async function login(credentials: LoginRequest): Promise<ApiResponse<LoginResponse>> {
  return apiClient.post<LoginResponse>('/auth/login', credentials);
}

export async function logout(): Promise<ApiResponse<unknown>> {
  return apiClient.post<unknown>('/auth/logout');
}

export async function getAuthStatus(): Promise<ApiResponse<AuthStatus>> {
  return apiClient.get<AuthStatus>('/auth/status');
}
