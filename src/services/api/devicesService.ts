// (10 Nov) Company mode: PCs that run the CyberGuard Agent (administrators see every PC, employees their own).
import { apiClient } from "./client";

export interface CollectorStatus {
  at: string;
  checked?: number;
  findings?: number;
  note?: string;
}

export interface DeviceRow {
  id: string;
  name: string;
  hostname: string;
  os: string;
  agentVersion: string;
  createdAt: string | null;
  lastSeen: string | null;
  lastIp: string;
  online: boolean;
  paired: boolean;
  owner: { id: string; name: string; email: string };
  findings24h: number;
  findingsTotal: number;
  highestRisk24h: number;
  lastFinding: { title: string; risk: number; at: string | null } | null;
  collectors: Record<string, CollectorStatus>;
  collectorsAvailable: string[];
  network: { summary: Record<string, number> | null; takenAt: string | null } | null;
}

export interface DeviceFinding {
  id: string;
  title: string;
  risk: number;
  classification: string;
  threatType: string;
  collector: string;
  at: string | null;
  explanation: string;
}

export interface DeviceDetail extends DeviceRow {
  networkLast: {
    takenAt: string;
    summary: Record<string, number>;
    findings: { severity: string; title: string; why: string; fix?: string[] }[];
    listening: { protocol: string; address: string; port: number; scope: string; program: string; service?: string }[];
    topRemote: { address: string; connections: number }[];
    topPrograms: { program: string; connections: number }[];
  } | null;
  recentDownloads: { name: string; score: number; at: string }[];
  findings: DeviceFinding[];
}

export interface DevicesResponse {
  admin: boolean;
  devices: DeviceRow[];
  summary: { total: number; online: number; withFindings24h: number; findings24h: number };
}

export interface NewDevice {
  id: string;
  name: string;
  key: string;
  server: string;
  note: string;
}

export const devicesService = {
  list: () => apiClient.get<DevicesResponse>("/api/devices"),
  get: (id: string) => apiClient.get<DeviceDetail>(`/api/devices/${encodeURIComponent(id)}`),
  create: (name: string, userId?: string) => apiClient.post<NewDevice>("/api/devices", { name, ...(userId ? { userId } : {}) }),
  remove: (id: string) => apiClient.delete<{ removed: boolean }>(`/api/devices/${encodeURIComponent(id)}`),
};
