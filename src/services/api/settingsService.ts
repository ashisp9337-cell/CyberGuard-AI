// Real, persisted user settings from the backend (GET/PUT /api/settings).
import { apiClient } from "./client";

export interface BackendSettings {
  sensitivity: string;
  notificationsEnabled: boolean;
  emailNotifications: boolean;
  integrationSettings: Record<string, unknown>;
  updatedAt: string;
}

export async function getSettings(): Promise<BackendSettings> {
  return apiClient.get<BackendSettings>("/api/settings");
}

export async function updateSettings(patch: Partial<{
  sensitivity: string; notificationsEnabled: boolean; emailNotifications: boolean; integrationSettings: Record<string, unknown>;
}>): Promise<BackendSettings> {
  return apiClient.put<BackendSettings>("/api/settings", patch);
}
