import type {
  LiveEvent, LogEntry, NetworkEvent, ScanHistoryEntry, SecurityReport,
  SecurityScoreSnapshot, Severity, Threat, ThreatActivityPoint, ThreatDistributionSlice,
} from "@/types";
import { generateId } from "@/lib/utils";

function daysAgoIso(days: number, hours = 0) {
  const d = new Date();
  d.setDate(d.getDate() - days);
  d.setHours(d.getHours() - hours);
  return d.toISOString();
}

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

const THREAT_TARGETS = [
  "invoice_march_2026.exe", "hr-portal-login.verify-account.net", "sms from +91-98XXX-4471",
  "ceo.transfer.request@corp-mail.co", "profile: @support_official_help", "meeting_notes.docx",
  "quarterly-report.pdf", "app-update-v2.apk", "192.168.14.22 → 45.83.201.7",
  "login: r.patel@company.com", "payslip_apr.zip", "video_call_recording.mp4",
  "wire-transfer-form.html", "192.168.14.9 (workstation-07)", "voice_message.mp3",
  "instagram DM from @official_support_team", "reset-password.secure-bank-login.com",
  "api-key rotation event #4471", "unusual download: 2.3GB from /finance/",
  "linkedin message from 'HR Director'",
];

const THREAT_TYPES: { type: string; category: Threat["category"] }[] = [
  { type: "Phishing Email", category: "phishing" },
  { type: "Malicious URL", category: "url-security" },
  { type: "Malware Detected", category: "cyber-threat" },
  { type: "Deepfake Audio", category: "deepfake" },
  { type: "Executive Impersonation", category: "impersonation" },
  { type: "Account Takeover Attempt", category: "credential" },
  { type: "Suspicious Login", category: "credential" },
  { type: "Data Exfiltration", category: "cyber-threat" },
  { type: "API Abuse", category: "cyber-threat" },
  { type: "Look-Alike Domain", category: "url-security" },
  { type: "Deepfake Video", category: "deepfake" },
  { type: "Brand Impersonation", category: "impersonation" },
];

function seededRandom(seed: number) {
  let s = seed;
  return () => {
    s = (s * 9301 + 49297) % 233280;
    return s / 233280;
  };
}

const rng = seededRandom(42);

export function generateThreats(count: number): Threat[] {
  const out: Threat[] = [];
  for (let i = 0; i < count; i++) {
    const tt = THREAT_TYPES[Math.floor(rng() * THREAT_TYPES.length)];
    const severity = SEVERITIES[Math.floor(rng() * SEVERITIES.length)];
    out.push({
      id: generateId("THR"),
      type: tt.type,
      category: tt.category,
      severity,
      target: THREAT_TARGETS[Math.floor(rng() * THREAT_TARGETS.length)],
      riskScore: Math.floor(rng() * 100),
      status: (["active", "investigating", "resolved", "blocked"] as const)[Math.floor(rng() * 4)],
      timestamp: daysAgoIso(Math.floor(rng() * 6), Math.floor(rng() * 23)),
    });
  }
  return out.sort((a, b) => (a.timestamp < b.timestamp ? 1 : -1));
}

const LIVE_TITLES: { severity: Severity; title: string; description: string; category: LiveEvent["category"] }[] = [
  { severity: "critical", title: "Potential malware detected", description: "Executable exhibits ransomware-like file encryption behavior.", category: "cyber-threat" },
  { severity: "high", title: "Phishing URL detected", description: "Outbound click to a domain flagged for credential harvesting.", category: "phishing" },
  { severity: "medium", title: "Suspicious login attempt detected", description: "Login attempt from an unrecognized device fingerprint.", category: "credential" },
  { severity: "critical", title: "Data exfiltration pattern identified", description: "Large outbound transfer to an unfamiliar external endpoint.", category: "cyber-threat" },
  { severity: "high", title: "Deepfake audio flagged", description: "Voice message shows spectral artifacts consistent with cloning.", category: "deepfake" },
  { severity: "medium", title: "Executive impersonation attempt", description: "Message impersonating a senior leader requesting a transfer.", category: "impersonation" },
  { severity: "low", title: "Routine file scan completed", description: "No indicators of compromise found in scanned batch.", category: "system" },
  { severity: "high", title: "Look-alike domain registered", description: "New domain closely resembles company's primary brand.", category: "url-security" },
  { severity: "critical", title: "Password spray attack detected", description: "Single password attempted against 40+ accounts within 3 minutes.", category: "credential" },
  { severity: "medium", title: "Unusual API request volume", description: "Client exceeded normal request rate by 6x baseline.", category: "api" },
  { severity: "high", title: "Insider data access anomaly", description: "Employee accessed records outside their normal scope.", category: "cyber-threat" },
  { severity: "info", title: "Threat intelligence feed updated", description: "1,204 new indicators of compromise ingested.", category: "system" },
];

export function generateLiveEvents(count: number, seedOffset = 0): LiveEvent[] {
  const localRng = seededRandom(100 + seedOffset);
  const out: LiveEvent[] = [];
  for (let i = 0; i < count; i++) {
    const t = LIVE_TITLES[Math.floor(localRng() * LIVE_TITLES.length)];
    out.push({
      id: generateId("EVT"),
      severity: t.severity,
      title: t.title,
      description: t.description,
      target: THREAT_TARGETS[Math.floor(localRng() * THREAT_TARGETS.length)],
      riskScore: Math.floor(localRng() * 100),
      status: (["active", "investigating", "resolved", "blocked"] as const)[Math.floor(localRng() * 4)],
      timestamp: new Date(Date.now() - i * 45_000).toISOString(),
      category: t.category,
    });
  }
  return out;
}

export function generateThreatActivity(range: "24h" | "7d" | "30d"): ThreatActivityPoint[] {
  const points: ThreatActivityPoint[] = [];
  const count = range === "24h" ? 12 : range === "7d" ? 7 : 30;
  const localRng = seededRandom(range === "24h" ? 7 : range === "7d" ? 77 : 777);
  for (let i = 0; i < count; i++) {
    const label = range === "24h" ? `${(i * 2).toString().padStart(2, "0")}:00`
      : range === "7d" ? ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"][i]
      : `Day ${i + 1}`;
    points.push({
      label,
      malware: Math.floor(localRng() * 12) + 1,
      phishing: Math.floor(localRng() * 18) + 2,
      deepfake: Math.floor(localRng() * 6),
      suspiciousUrls: Math.floor(localRng() * 15) + 1,
      accountTakeover: Math.floor(localRng() * 8),
      networkThreats: Math.floor(localRng() * 10) + 1,
    });
  }
  return points;
}

export function getThreatDistribution(): ThreatDistributionSlice[] {
  return [
    { name: "Phishing", value: 32, color: "#f97316" },
    { name: "Malware", value: 22, color: "#ef4444" },
    { name: "Malicious URLs", value: 18, color: "#22c55e" },
    { name: "Credential Theft", value: 12, color: "#38bdf8" },
    { name: "Deepfake", value: 9, color: "#a855f7" },
    { name: "Impersonation", value: 7, color: "#eab308" },
  ];
}

export function getSecurityScore(): SecurityScoreSnapshot {
  return { score: 92, status: "PROTECTED", critical: 2, high: 5, medium: 8, low: 9 };
}

export function generateScanHistory(count: number): ScanHistoryEntry[] {
  const localRng = seededRandom(321);
  const out: ScanHistoryEntry[] = [];
  const modules: ScanHistoryEntry["moduleId"][] = ["phishing", "deepfake", "impersonation", "credential", "url-security", "cyber-threat"];
  for (let i = 0; i < count; i++) {
    const risk = Math.floor(localRng() * 100);
    const severity: Severity = risk > 85 ? "critical" : risk > 70 ? "high" : risk > 50 ? "medium" : "low";
    out.push({
      scanId: generateId("SCN"),
      target: THREAT_TARGETS[Math.floor(localRng() * THREAT_TARGETS.length)],
      targetType: (["text", "url", "file", "email", "identity"] as const)[Math.floor(localRng() * 5)],
      threatType: THREAT_TYPES[Math.floor(localRng() * THREAT_TYPES.length)].type,
      moduleId: modules[Math.floor(localRng() * modules.length)],
      riskScore: risk,
      severity,
      date: daysAgoIso(Math.floor(localRng() * 30), Math.floor(localRng() * 23)),
      status: (["completed", "flagged", "cleared", "escalated"] as const)[Math.floor(localRng() * 4)],
    });
  }
  return out.sort((a, b) => (a.date < b.date ? 1 : -1));
}

export function generateNetworkEvents(count: number): NetworkEvent[] {
  const localRng = seededRandom(555);
  const out: NetworkEvent[] = [];
  const protocols = ["TCP", "UDP", "HTTPS", "DNS", "SSH", "FTP"];
  for (let i = 0; i < count; i++) {
    const score = Math.floor(localRng() * 100);
    out.push({
      id: generateId("NET"),
      source: `192.168.${Math.floor(localRng() * 20) + 1}.${Math.floor(localRng() * 254) + 1}`,
      destination: `${Math.floor(localRng() * 223) + 1}.${Math.floor(localRng() * 254)}.${Math.floor(localRng() * 254)}.${Math.floor(localRng() * 254)}`,
      protocol: protocols[Math.floor(localRng() * protocols.length)],
      trafficVolume: `${(localRng() * 500).toFixed(1)} MB`,
      threatScore: score,
      status: score > 70 ? "blocked" : score > 40 ? "suspicious" : "normal",
    });
  }
  return out;
}

const LOG_LINES: { level: LogEntry["level"]; source: string; message: string }[] = [
  { level: "normal", source: "auth-service", message: "User r.patel@company.com authenticated successfully via SSO." },
  { level: "normal", source: "scan-engine", message: "Scheduled malware scan completed on 214 endpoints — no threats found." },
  { level: "warning", source: "firewall", message: "Repeated connection attempts from 45.83.201.7 rate-limited." },
  { level: "suspicious", source: "auth-service", message: "5 failed login attempts for account admin@company.com within 90s." },
  { level: "critical", source: "endpoint-agent", message: "workstation-07 flagged: process powershell.exe spawned encoded command." },
  { level: "normal", source: "api-gateway", message: "Token refreshed for client cg-mobile-app-prod." },
  { level: "suspicious", source: "dlp-monitor", message: "2.3GB outbound transfer from /finance/ to unrecognized external host." },
  { level: "critical", source: "ids", message: "Signature match: known ransomware C2 beacon pattern on 192.168.14.9." },
  { level: "normal", source: "backup-service", message: "Nightly backup job completed successfully." },
  { level: "warning", source: "vpn-gateway", message: "Login from unrecognized device fingerprint for user s.iyer@company.com." },
  { level: "normal", source: "scan-engine", message: "Threat intelligence feed synced — 1,204 new indicators ingested." },
  { level: "critical", source: "email-gateway", message: "Blocked phishing email impersonating finance department to 14 recipients." },
];

export function generateLogs(count: number): LogEntry[] {
  const localRng = seededRandom(909);
  const out: LogEntry[] = [];
  for (let i = 0; i < count; i++) {
    const line = LOG_LINES[Math.floor(localRng() * LOG_LINES.length)];
    out.push({
      id: generateId("LOG"),
      timestamp: new Date(Date.now() - i * 21_000).toISOString(),
      level: line.level,
      source: line.source,
      message: line.message,
    });
  }
  return out;
}

export function generateReports(): SecurityReport[] {
  const types = [
    "Executive Security Summary", "Threat Analysis Report", "Malware Analysis Report",
    "Phishing Investigation Report", "Account Security Report", "Network Security Report",
  ];
  return types.map((type, i) => ({
    id: generateId("RPT"),
    title: `${type} — ${new Date(daysAgoIso(i * 3)).toLocaleDateString(undefined, { month: "short", day: "numeric" })}`,
    type,
    createdAt: daysAgoIso(i * 3),
    format: (["PDF", "JSON", "CSV"] as const)[i % 3],
    sizeKb: Math.floor(120 + rng() * 900),
  }));
}
