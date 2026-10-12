// Look a URL up in external threat-intelligence feeds (GET /api/threat-intelligence/lookup).
// Providers without an API key report "unavailable" instead of a made-up verdict.
import { apiClient } from "./client";

export interface ProviderResult {
  provider: string;
  status: "ok" | "not_found" | "unavailable" | "error" | "skipped" | string;
  reason?: string;
  stats?: Record<string, number>;
  query_status?: string;
  threat?: string | null;
  [key: string]: unknown;
}

export interface LookupResult {
  url: string;
  virustotal: ProviderResult;
  urlhaus: ProviderResult;
}

export async function lookupUrl(url: string): Promise<LookupResult> {
  return apiClient.get<LookupResult>(`/api/threat-intelligence/lookup?url=${encodeURIComponent(url)}`);
}
