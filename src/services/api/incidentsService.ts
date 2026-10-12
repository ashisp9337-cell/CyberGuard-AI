// Incident workflow (GET/PATCH /api/incidents). Every high/critical threat is an incident
// that moves open -> investigating -> resolved (or false positive).
import { apiClient } from "./client";
import { API_CONFIG } from "./config";
import type { MitreTechnique } from "@/types";

export type IncidentStatus = "open" | "investigating" | "resolved" | "false_positive";

export interface Incident {
  id: string;
  title: string;
  severity: "high" | "critical";
  category: string;
  riskScore: number;
  target: string;
  scanId: string | null;
  createdAt: string;
  status: IncidentStatus;
  statusLabel: string;
  resolvedAt: string | null;
  history: { from: string; status: IncidentStatus; by: string; at: string; note: string }[];
  alertedVia: string[];
  seenBefore?: boolean;
  mitre?: MitreTechnique[];
}

export interface IncidentSummary {
  total: number;
  counts: Record<IncidentStatus, number>;
  active: number;
  openCritical: number;
  mttrMinutes: number | null;
}

const now = () => new Date().toISOString();
const MOCK: Incident[] = [
  { id: "EVT_demo1", title: "Multiple Failed Login Attempts — Critical", severity: "critical", category: "credential",
    riskScore: 90, target: "root@srv from 185.220.101.4", scanId: null, createdAt: now(), status: "open",
    statusLabel: "Open", resolvedAt: null, history: [], alertedVia: ["telegram"] },
  { id: "EVT_demo2", title: "SMS / Message Analysis — High Risk", severity: "high", category: "phishing",
    riskScore: 85, target: "Dear SBI customer, your YONO account…", scanId: null, createdAt: now(),
    status: "investigating", statusLabel: "Investigating", resolvedAt: null, history: [], alertedVia: [] },
];

export async function fetchIncidents(status = "active", limit = 8): Promise<Incident[]> {
  if (API_CONFIG.useMockData) return MOCK;
  return apiClient.get<Incident[]>(`/api/incidents?status=${status}&limit=${limit}`);
}

export async function fetchIncidentSummary(): Promise<IncidentSummary> {
  if (API_CONFIG.useMockData) {
    return { total: 5, counts: { open: 1, investigating: 1, resolved: 3, false_positive: 0 }, active: 2,
             openCritical: 1, mttrMinutes: 42 };
  }
  return apiClient.get<IncidentSummary>("/api/incidents/summary");
}

export async function updateIncidentStatus(id: string, status: IncidentStatus, note = ""): Promise<Incident> {
  return apiClient.patch<Incident>(`/api/incidents/${id}`, { status, note });
}

export interface BulkResult {
  matched: number;
  changed: number;
  status: IncidentStatus;
  summary: IncidentSummary;
}

/** Change many incidents at once: the ticked ids, or scope "active" = every open + investigating incident. */
export async function bulkUpdateIncidents(
  status: IncidentStatus, opts: { ids?: string[]; scope?: "active" }, note = "",
): Promise<BulkResult> {
  return apiClient.post<BulkResult>("/api/incidents/bulk", { status, note, ids: opts.ids ?? [], scope: opts.scope ?? null });
}

/** "Escalate to Team": turn a scan into an open incident and alert the security team now. */
export async function escalateScan(scanId: string, note = ""): Promise<{ incident: Incident; alertChannels: string[] }> {
  return apiClient.post<{ incident: Incident; alertChannels: string[] }>("/api/incidents/escalate", { scanId, note });
}

