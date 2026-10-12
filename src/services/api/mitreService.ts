// MITRE ATT&CK view (GET /api/mitre/summary, /api/mitre/techniques): which attacker techniques
// CyberGuard has seen in your own scans, each explained in plain language.
import { apiClient } from "./client";
import type { MitreTechnique } from "@/types";

export interface MitreSeen extends MitreTechnique {
  count: number;
  lastSeen: string | null;
  modules: string[];
  example: { scanId: string; target: string; riskScore: number } | null;
}

export interface MitreSummary {
  days: number;
  mappedScans: number;
  techniques: MitreSeen[];
  tactics: { tactic: string; count: number }[];
}

export async function getMitreSummary(days = 30): Promise<MitreSummary> {
  return apiClient.get<MitreSummary>(`/api/mitre/summary?days=${days}`);
}

export async function listMitreTechniques(): Promise<MitreTechnique[]> {
  return apiClient.get<MitreTechnique[]>("/api/mitre/techniques");
}
