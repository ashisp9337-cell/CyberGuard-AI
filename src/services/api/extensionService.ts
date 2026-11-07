// (6 Nov) Browser extension connection keys: one key per connected browser; the key is shown only once.
import { apiClient } from "./client";

export interface ExtensionKey {
  id: string;
  label: string;
  createdAt: string | null;
  lastUsedAt: string | null;
}

export interface NewExtensionKey {
  id: string;
  label: string;
  token: string;
  note: string;
}

export async function listExtensionKeys(): Promise<ExtensionKey[]> {
  return apiClient.get<ExtensionKey[]>("/api/extension/tokens");
}

export async function createExtensionKey(label: string): Promise<NewExtensionKey> {
  return apiClient.post<NewExtensionKey>("/api/extension/tokens", { label });
}

export async function deleteExtensionKey(id: string): Promise<void> {
  await apiClient.delete(`/api/extension/tokens/${encodeURIComponent(id)}`);
}
