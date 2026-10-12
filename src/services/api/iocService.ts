// Indicators of Compromise remembered from earlier risky scans (GET/PATCH /api/iocs).
import { apiClient } from "./client";

export type IocType = "url" | "domain" | "ip" | "email" | "sha256";

export interface Ioc {
  id: string;
  type: IocType;
  value: string;
  status: "active" | "allowlisted";
  timesSeen: number;
  maxRisk: number;
  modules: string[];
  firstSeen: string | null;
  lastSeen: string | null;
  lastScanId: string | null;
  note: string;
}

export interface IocSummary {
  total: number;
  allowlisted: number;
  byType: Record<IocType, number>;
  repeat: number;
  top: Ioc[];
}

export async function listIocs(params: { type?: string; q?: string; status?: string } = {}): Promise<Ioc[]> {
  const qs = new URLSearchParams({ limit: "200", ...Object.fromEntries(Object.entries(params).filter(([, v]) => v)) });
  return apiClient.get<Ioc[]>(`/api/iocs?${qs.toString()}`);
}

export async function getIocSummary(): Promise<IocSummary> {
  return apiClient.get<IocSummary>("/api/iocs/summary");
}

export async function setIocStatus(id: string, status: "active" | "allowlisted", note = ""): Promise<Ioc> {
  return apiClient.patch<Ioc>(`/api/iocs/${id}`, { status, note });
}

export async function downloadIocCsv(): Promise<void> {
  const blob = await apiClient.get<Blob>("/api/iocs/export.csv");
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "cyberguard_iocs.csv";
  a.click();
  URL.revokeObjectURL(url);
}
