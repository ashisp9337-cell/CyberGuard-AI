// Email quarantine (GET /api/email/quarantine, POST /api/email/records/{id}/action).
import { apiClient } from "./client";
import { API_CONFIG } from "./config";

export type QuarantineStatus = "quarantined" | "released" | "deleted";

export interface QuarantinedEmail {
  id: string;
  scanId: string | null;
  from: string;
  displayName: string;
  subject: string;
  category: string;
  riskScore: number;
  classification: string;
  status: QuarantineStatus | "none";
  reason: string;
  history: { action: string; by: string; at: string; note: string }[];
  createdAt: string | null;
}

export interface QuarantineList {
  counts: Record<QuarantineStatus, number>;
  items: QuarantinedEmail[];
}

export async function fetchQuarantine(status = "quarantined", limit = 6): Promise<QuarantineList> {
  if (API_CONFIG.useMockData) {
    return {
      counts: { quarantined: 1, released: 0, deleted: 2 },
      items: [{
        id: "EML_demo", scanId: null, from: "alerts@sbi-kyc-verify.com", displayName: "SBI Alerts",
        subject: "Your YONO account will be blocked today", category: "Credential phishing", riskScore: 94,
        classification: "critical", status: "quarantined", reason: "Risk 94/100 (critical): Credential phishing",
        history: [], createdAt: new Date().toISOString(),
      }],
    };
  }
  return apiClient.get<QuarantineList>(`/api/email/quarantine?status=${status}&limit=${limit}`);
}

export async function quarantineAction(id: string, action: "release" | "quarantine" | "delete", note = "") {
  return apiClient.post<QuarantinedEmail>(`/api/email/records/${id}/action`, { action, note });
}
