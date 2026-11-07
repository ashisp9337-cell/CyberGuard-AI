// Real, persisted user settings from the backend (GET/PUT /api/settings).
import { apiClient } from "./client";

export interface BackendSettings {
  sensitivity: string;
  notificationsEnabled: boolean;
  emailNotifications: boolean;
  integrationSettings: Record<string, unknown>;
  /** (4 Nov) alerts for the background watchers' findings: "critical" (default) or "same" as my scans */
  automaticAlerts?: "critical" | "same";
  updatedAt: string;
}

export async function getSettings(): Promise<BackendSettings> {
  return apiClient.get<BackendSettings>("/api/settings");
}

export async function updateSettings(patch: Partial<{
  sensitivity: string; notificationsEnabled: boolean; emailNotifications: boolean; integrationSettings: Record<string, unknown>;
  automaticAlerts: "critical" | "same";
}>): Promise<BackendSettings> {
  return apiClient.put<BackendSettings>("/api/settings", patch);
}
