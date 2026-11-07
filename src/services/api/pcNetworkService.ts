// (6 Nov) Live, read-only view of this computer's open ports and network connections (administrator only).
import { apiClient } from "./client";

export interface PcFinding {
  severity: "high" | "medium" | "low";
  title: string;
  why: string;
  port?: number;
  remote?: string;
  program?: string;
  pid?: number | null;
}

export interface PcListening {
  protocol: string;
  address: string;
  port: number;
  scope: "this computer only" | "your network" | "all networks" | string;
  program: string;
  pid: number | null;
  service: string;
}

export interface PcConnection {
  protocol: string;
  local: string;
  remote: string;
  remotePort: number;
  status: string;
  program: string;
  pid: number | null;
  outside: boolean;
}

export interface PcSnapshot {
  available: boolean;
  reason?: string;
  takenAt?: string;
  summary?: { openPorts: number; openToNetwork: number; connections: number; toInternet: number; programs: number;
              high: number; medium: number; byStatus: Record<string, number> };
  findings?: PcFinding[];
  listening?: PcListening[];
  connections?: PcConnection[];
  truncated?: boolean;
  topRemote?: { address: string; connections: number }[];
  topPrograms?: { program: string; connections: number }[];
  note?: string;
}

export async function getPcNetwork(): Promise<PcSnapshot> {
  return apiClient.get<PcSnapshot>("/api/pc-network");
}
