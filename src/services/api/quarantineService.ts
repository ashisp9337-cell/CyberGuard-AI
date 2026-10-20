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
  /** Set when the Gmail watcher moved the real email: "moved" (in the CyberGuard-Quarantine label),
   *  "released" (back in the inbox) or "move-failed". */
  mailbox: { status: string; label: string } | null;
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
        history: [], mailbox: null, createdAt: new Date().toISOString(),
      }],
    };
  }
  return apiClient.get<QuarantineList>(`/api/email/quarantine?status=${status}&limit=${limit}`);
}

export async function quarantineAction(id: string, action: "release" | "quarantine" | "delete", note = "") {
  return apiClient.post<QuarantinedEmail>(`/api/email/records/${id}/action`, { action, note });
}

// ---- Quarantined downloads (admin only): GET /api/quarantine/files, POST /api/quarantine/files/{id}/restore ----
export interface QuarantinedFile {
  id: string;
  name: string;
  originalPath: string;
  size: number;
  sha256: string;
  score: number;
  reason: string;
  scanId: string | null;
  status: "quarantined" | "restored";
  quarantinedAt: string;
  restoredAt: string | null;
  restoredTo: string | null;
}

export interface FileQuarantineList {
  enabled: boolean;
  minScore: number;
  counts: { quarantined: number; restored: number };
  items: QuarantinedFile[];
}

export async function fetchFileQuarantine(status = "quarantined"): Promise<FileQuarantineList> {
  return apiClient.get<FileQuarantineList>(`/api/quarantine/files?status=${status}`);
}

export async function restoreFile(id: string): Promise<QuarantinedFile> {
  return apiClient.post<QuarantinedFile>(`/api/quarantine/files/${encodeURIComponent(id)}/restore`, {});
}
