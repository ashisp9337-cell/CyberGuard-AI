// Real scan history from the backend (GET/DELETE /api/scans).
import type { ScanHistoryEntry, AnalysisResult } from "@/types";
import { apiClient } from "./client";
import { API_CONFIG } from "./config";

export interface ScanListResult {
  items: ScanHistoryEntry[];
  total: number;
  page: number;
  pageSize: number;
}

export async function listScans(params: {
  page?: number; pageSize?: number; module?: string; severity?: string; search?: string;
} = {}): Promise<ScanListResult> {
  if (API_CONFIG.useMockData) {
    const { generateScanHistory } = await import("@/services/mock/mockData");
    const items = generateScanHistory(28);
    return { items, total: items.length, page: 1, pageSize: items.length };
  }
  const qs = new URLSearchParams();
  if (params.page) qs.set("page", String(params.page));
  if (params.pageSize) qs.set("pageSize", String(params.pageSize));
  if (params.module) qs.set("module", params.module);
  if (params.severity) qs.set("severity", params.severity);
  if (params.search) qs.set("search", params.search);
  return apiClient.get<ScanListResult>(`/api/scans?${qs.toString()}`);
}

export async function getScan(scanId: string): Promise<AnalysisResult> {
  return apiClient.get<AnalysisResult>(`/api/scans/${scanId}`);
}

export async function deleteScan(scanId: string): Promise<void> {
  await apiClient.delete(`/api/scans/${scanId}`);
}
