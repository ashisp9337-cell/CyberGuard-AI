// Per-user "known contacts" used by the Friend/Relative/Known Contact
// Impersonation detector (backend: /api/contacts). This is personal data —
// each user manages their own list under Settings.
import { apiClient } from "./client";

export interface KnownContact {
  id: string;
  displayName: string;
  roleLabel: string;
  authorizedEmail: string;
  authorizedDomain: string;
  typicalHoursStart: number;
  typicalHoursEnd: number;
  highRiskRequestsAllowed: boolean;
  notes: string;
  createdAt: string;
  updatedAt: string;
}

export interface ContactInput {
  displayName: string;
  roleLabel?: string;
  authorizedEmail?: string;
  authorizedDomain?: string;
  typicalHoursStart?: number;
  typicalHoursEnd?: number;
  highRiskRequestsAllowed?: boolean;
  notes?: string;
}

export async function listContacts(): Promise<KnownContact[]> {
  return apiClient.get<KnownContact[]>("/api/contacts");
}

export async function createContact(input: ContactInput): Promise<KnownContact> {
  return apiClient.post<KnownContact>("/api/contacts", input);
}

export async function updateContact(id: string, patch: Partial<ContactInput>): Promise<KnownContact> {
  return apiClient.put<KnownContact>(`/api/contacts/${id}`, patch);
}

export async function deleteContact(id: string): Promise<void> {
  await apiClient.delete<void>(`/api/contacts/${id}`);
}

// (11 Nov) Import from a phone / Google / Outlook contacts export (.vcf or .csv). Only names and the first e-mail
// are kept - phone numbers and everything else in the file are ignored by the server and never stored.
export interface ContactImportResult {
  format: string;
  imported: number;
  duplicates: number;
  withoutName: number;
  overLimit: number;
  total: number;
}

export async function importContacts(file: File): Promise<ContactImportResult> {
  const form = new FormData();
  form.append("file", file);
  return apiClient.post<ContactImportResult>("/api/contacts/import", form);
}

export async function deleteAllContacts(): Promise<{ removed: number }> {
  return apiClient.delete<{ removed: number }>("/api/contacts");
}
