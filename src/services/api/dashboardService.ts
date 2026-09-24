// Real dashboard data from the backend (GET /api/dashboard/*). Falls back
// to the local mock generators only when VITE_USE_MOCK_DATA=true.
import type {
  SecurityScoreSnapshot, ThreatActivityPoint, ThreatDistributionSlice, LiveEvent,
} from "@/types";
import { apiClient } from "./client";
import { API_CONFIG } from "./config";

export interface DashboardOverview {
  securityScore: number;
  status: "PROTECTED" | "AT RISK" | "CRITICAL";
  activeThreats: number;
  totalScans: number;
  criticalThreats: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export async function fetchOverview(): Promise<DashboardOverview> {
  if (API_CONFIG.useMockData) {
    const { getSecurityScore } = await import("@/services/mock/mockData");
    const snap = getSecurityScore();
    return {
      securityScore: snap.score, status: snap.status,
      activeThreats: snap.critical + snap.high + snap.medium + snap.low,
      totalScans: 0, criticalThreats: snap.critical,
      critical: snap.critical, high: snap.high, medium: snap.medium, low: snap.low,
    };
  }
  return apiClient.get<DashboardOverview>("/api/dashboard/overview");
}

export function overviewToSecurityScoreSnapshot(o: DashboardOverview): SecurityScoreSnapshot {
  return { score: o.securityScore, status: o.status, critical: o.critical, high: o.high, medium: o.medium, low: o.low };
}

export async function fetchActivity(days = 14): Promise<ThreatActivityPoint[]> {
  if (API_CONFIG.useMockData) {
    const { generateThreatActivity } = await import("@/services/mock/mockData");
    return generateThreatActivity(days <= 1 ? "24h" : days <= 7 ? "7d" : "30d") as unknown as ThreatActivityPoint[];
  }
  return apiClient.get<ThreatActivityPoint[]>(`/api/dashboard/activity?days=${days}`);
}

export async function fetchThreatDistribution(): Promise<ThreatDistributionSlice[]> {
  if (API_CONFIG.useMockData) {
    const { getThreatDistribution } = await import("@/services/mock/mockData");
    return getThreatDistribution();
  }
  const data = await apiClient.get<{ name: string; value: number; color: string }[]>("/api/dashboard/threat-distribution");
  const total = data.reduce((sum, d) => sum + d.value, 0) || 1;
  return data.map((d) => ({ ...d, value: Math.round((d.value / total) * 100) }));
}

export async function fetchLiveFeed(limit = 20): Promise<LiveEvent[]> {
  if (API_CONFIG.useMockData) {
    const { generateLiveEvents } = await import("@/services/mock/mockData");
    return generateLiveEvents(limit);
  }
  const events = await apiClient.get<any[]>(`/api/dashboard/live-feed?limit=${limit}`);
  return events.map((e) => ({
    id: e.id, severity: e.severity, title: e.title, description: e.description,
    target: e.target ?? "", riskScore: e.riskScore ?? 0, status: e.status ?? "active",
    timestamp: e.timestamp, category: e.category ?? "system",
  }));
}
