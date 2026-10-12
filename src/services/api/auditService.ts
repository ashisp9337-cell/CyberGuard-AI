// Activity (audit) log: sign-ins, failed sign-ins, settings and incident actions (GET /api/audit).
import { apiClient } from "./client";

export interface AuditEntry {
  id: string;
  action: string;
  label: string;
  actor: string;
  target: string;
  detail: Record<string, unknown>;
  ip: string;
  userAgent: string;
  success: boolean;
  at: string;
}

export async function listAudit(limit = 50): Promise<AuditEntry[]> {
  return apiClient.get<AuditEntry[]>(`/api/audit?limit=${limit}`);
}
