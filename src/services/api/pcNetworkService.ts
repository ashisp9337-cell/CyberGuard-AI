// (6 Nov) Live view of this computer's open ports and network connections (administrator only).
// (10 Nov) + actions: block a port / an address (Windows Firewall, undoable), close a connection, end a program.
import { apiClient } from "./client";

export interface PcFinding {
  severity: "high" | "medium" | "low";
  title: string;
  why: string;
  port?: number;
  remote?: string;
  program?: string;
  pid?: number | null;
  /** (7 Nov) concrete next steps for this kind of finding, most important first */
  fix?: string[];
  /** (10 Nov) the program may be ended from the page (Windows' own programs, the database and CyberGuard may not) */
  canEnd?: boolean;
}

export interface PcListening {
  protocol: string;
  address: string;
  port: number;
  scope: "this computer only" | "your network" | "all networks" | string;
  program: string;
  pid: number | null;
  service: string;
  canEnd?: boolean;
}

export interface PcConnection {
  protocol: string;
  local: string;
  localAddress: string;
  localPort: number;
  remote: string;
  remotePort: number;
  status: string;
  program: string;
  pid: number | null;
  outside: boolean;
  /** (10 Nov) what the remote port usually is, e.g. "secure web (HTTPS)" */
  remoteService?: string;
  /** (10 Nov) "the internet" / "your local network ..." / "this computer ..." */
  where?: string;
  /** (10 Nov) reverse-DNS name of the remote address and the organisation it belongs to */
  remoteName?: string;
  owner?: string;
  canEnd?: boolean;
}

export interface PcPortStatus {
  port: number;
  service: string;
  state: "open" | "closed";
  scope: string;
  program: string;
  pid: number | null;
  risk: "high" | "medium" | "low" | "none";
  canEnd?: boolean;
}

export interface PcActions {
  enabled: boolean;
  reason: string;
  admin?: boolean;
  windows?: boolean;
  firewall?: boolean;
  closeConnection?: boolean;
  endProcess?: boolean;
}

export interface PcBlock {
  name: string;
  /** (10 Nov) "program" = one program cut off from one address */
  kind: "port" | "address" | "program";
  program?: string;
  port?: number;
  protocol?: string;
  address?: string;
  at: string;
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
  portStatus?: PcPortStatus[];
  stateMeaning?: Record<string, string>;
  actions?: PcActions;
  blocked?: PcBlock[];
}

export interface PcActionResult { ok: boolean; message: string; rule?: string }

export async function getPcNetwork(): Promise<PcSnapshot> {
  return apiClient.get<PcSnapshot>("/api/pc-network");
}

export async function blockPort(port: number, protocol = "TCP"): Promise<PcActionResult> {
  return apiClient.post<PcActionResult>("/api/pc-network/block-port", { port, protocol });
}

export async function blockAddress(address: string): Promise<PcActionResult> {
  return apiClient.post<PcActionResult>("/api/pc-network/block-address", { address });
}

export async function unblock(name: string): Promise<PcActionResult> {
  return apiClient.post<PcActionResult>("/api/pc-network/unblock", { name });
}

export async function closeConnection(c: PcConnection): Promise<PcActionResult> {
  return apiClient.post<PcActionResult>("/api/pc-network/close-connection", {
    localAddress: c.localAddress, localPort: c.localPort, remoteAddress: c.remote, remotePort: c.remotePort });
}

export async function endProcess(pid: number, name: string): Promise<PcActionResult> {
  return apiClient.post<PcActionResult>("/api/pc-network/end-process", { pid, name });
}

/** (10 Nov) Cut one program off from one address: firewall rule for that program + the live connection dropped. */
export async function cutOff(c: PcConnection): Promise<PcActionResult> {
  return apiClient.post<PcActionResult>("/api/pc-network/cut-off", {
    pid: c.pid, name: c.program, remoteAddress: c.remote,
    localAddress: c.localAddress, localPort: c.localPort, remotePort: c.remotePort });
}
