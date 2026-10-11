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