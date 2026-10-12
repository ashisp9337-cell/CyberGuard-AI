// Automatic protection: background watchers (Gmail inbox, CyberGuard sign-ins, Windows sign-ins, Downloads folder).
import { apiClient } from "./client";

export interface WatcherStatus {
  name: "email" | "logins" | "windows" | "downloads" | string;
  title: string;
  what: string;
  modules: string[];
  technology: string;
  intervalSeconds: number;
  enabled: boolean;
  configured: boolean;
  setupHint: string;
  state: "active" | "off" | "needs setup" | "error" | string;
  running: boolean;
  lastCheck: string | null;
  lastError: string | null;
  checked: number;
  threats: number;
  lastFinding: string | null;
  note: string;
  recent: { at: string; item: string; score: number; classification: string }[];
}

export interface AutomationStatus {
  enabled: boolean;
  watchers: WatcherStatus[];
}

export async function getAutomationStatus(): Promise<AutomationStatus> {
  return apiClient.get<AutomationStatus>("/api/automation/status");
}

export async function setWatcherEnabled(name: string, enabled: boolean): Promise<WatcherStatus> {
  return apiClient.post<WatcherStatus>(`/api/automation/${name}/toggle`, { enabled });
}

export async function runWatcherNow(name: string): Promise<WatcherStatus> {
  return apiClient.post<WatcherStatus>(`/api/automation/${name}/run`, {});
}
