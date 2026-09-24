// Real report generation/listing/download from the backend (/api/reports).
import type { SecurityReport } from "@/types";
import { apiClient } from "./client";
import { API_CONFIG } from "./config";

export async function listReports(): Promise<SecurityReport[]> {
  if (API_CONFIG.useMockData) {
    const { generateReports } = await import("@/services/mock/mockData");
    return generateReports();
  }
  const reports = await apiClient.get<any[]>("/api/reports");
  return reports.map((r) => ({ id: r.id, title: r.title, type: r.type, createdAt: r.createdAt, format: r.format, sizeKb: r.sizeKb }));
}

export async function createReport(title: string, format: "PDF" | "CSV" | "JSON", scanIds?: string[]): Promise<SecurityReport> {
  const r = await apiClient.post<any>("/api/reports", { title, format, scanIds });
  return { id: r.id, title: r.title, type: r.type, createdAt: r.createdAt, format: r.format, sizeKb: r.sizeKb };
}

export function downloadReportUrl(reportId: string): string {
  return `${API_CONFIG.baseUrl}/api/reports/${reportId}/download`;
}
