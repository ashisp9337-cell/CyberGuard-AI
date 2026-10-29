// ============================================================
// CYBERGUARD AI — Core Type Definitions
// ============================================================

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type RiskClassification =
  | "safe"
  | "low_risk"
  | "suspicious"
  | "high_risk"
  | "critical"
  | "unverified";

export type ScanStatus =
  | "idle"
  | "queued"
  | "scanning"
  | "completed"
  | "failed";

export type InputKind = "text" | "url" | "file" | "email" | "identity";

export type DetectionModuleId =
  | "phishing"
  | "deepfake"
  | "impersonation"
  | "credential"
  | "url-security"
  | "cyber-threat";

// ---- Detection module & subtopic configuration -------------

export interface SubtopicConfig {
  id: string;
  moduleId: DetectionModuleId;
  title: string;
  description: string;
  icon: string; // lucide icon name, resolved via icon map
  inputKind: InputKind;
  supportedInput: string; // human readable, e.g. "Paste text or upload .eml"
  acceptedFileTypes?: string[];
  maxFileSizeMb?: number;
  placeholder?: string;
  indicatorPool: IndicatorTemplate[];
  extraFields?: { id: string; label: string; placeholder: string }[];
}

export interface DetectionModule {
  id: DetectionModuleId;
  name: string;
  shortName: string;
  description: string;
  icon: string;
  color: string; // tailwind-safe hex for module accent
  subtopics: SubtopicConfig[];
}

// ---- Indicators & analysis results --------------------------

export interface IndicatorTemplate {
  label: string;
  description: string;
  severity: Severity;
  weight: number; // contributes to risk score when triggered
}

export interface DetectedIndicator extends IndicatorTemplate {
  id: string;
  triggered: boolean;
  mitre?: string[]; // MITRE ATT&CK technique IDs this indicator is evidence of
}

// A MITRE ATT&CK technique, explained in plain language (backend app/services/mitre.py).
export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  explanation: string;
  url: string;
  evidence?: string[];
}

export interface IocHit {
  type: string;
  value: string;
  timesSeen: number;
  maxRisk: number;
}

export interface EngineScore {
  component: string;
  engine: string;
  score: number;
  classification: string | null;
  explanation: string;
}

export interface EmailSummary {
  from: string;
  displayName: string;
  subject: string;
  replyTo: string;
  originatingIp: string;
  spf: string;
  dkim: string;
  dmarc: string;
  links: number;
  attachments: number;
  escalations: string[];
}

export interface ScanStage {
  id: string;
  label: string;
}

export interface AnalysisResult {
  scanId: string;
  moduleId: DetectionModuleId;
  subtopicId: string;
  subtopicTitle: string;
  target: string; // filename, URL, or truncated text
  targetType: InputKind;
  riskScore: number; // 0-100
  classification: RiskClassification;
  confidenceScore: number; // 0-100
  detectionTime: string; // ISO timestamp
  analysisEngine: string;
  threatType: string;
  severity: Severity;
  indicators: DetectedIndicator[];
  explanation: string;
  recommendations: string[];
  responseActions?: ResponseAction[];
  quarantine?: { status: "quarantined" | "delivered"; auto: boolean; reason: string; at: string } | null;
  status: ScanStatus;
  mitreAttack?: MitreTechnique[];
  iocHits?: IocHit[];
  modelAssessment?: { site: string; probability: number; threshold: number; flagged: boolean } | null;
  engineBreakdown?: EngineScore[];
  emailSummary?: EmailSummary;
  category?: string | null;
  parsedSignals?: Record<string, unknown> | null;
  autoDetect?: AutoDetectInfo | null;
  modelDetails?: ModelDetail[];
  provenance?: ProvenanceInfo | null;
  liveCheck?: LiveCheckInfo | null;
  checkedDetectors?: { detector: string; riskScore: number }[];
  insiderRisk?: InsiderRiskInfo | null;
  malwareAnalysis?: MalwareAnalysisInfo | null;
  windowsEvents?: WindowsEventsInfo | null;
}

// Windows event-log incidents (backend app/services/scan_store.py _windows_events)
export interface WindowsEventsInfo {
  format: string;
  events: number;
  hosts: number;
  users: number;
  timeRange: string[] | null;
  activityDays: number;
  incidents: { rule: string; label: string; user: string; host: string; severity: string; mitre: string; lens: string;
               count: number; first: string; last: string; examples: string[] }[];
}

// Uploaded-file malware check (backend app/services/scan_store.py _malware_analysis)
export interface MalwareAnalysisInfo {
  fileName: string;
  size: number;
  sha256: string;
  detectedType: string;
  modelAvailable: boolean;
  virusTotal: string;
  targets: { name: string; fileType: string; score: number | null; level: string; alertLevel: number | null; checkLevel: number | null }[];
  archiveFiles: string[];
  notes: string[];
}

// Insider Risk triage queue (backend app/services/scan_store.py _insider_risk)
export interface InsiderQueueEntry {
  user: string;
  level: string; // "alert" | "review"
  risk: number | null; // percentile of ordinary working days
  score: number;
  date: string;
  flaggedDays: number;
  alertDays: number;
  historyDays: number;
  exfiltration: string[];
  abnormal: string[];
  pattern: { name: string; strength: string; why: string } | null;
  mitre: string[];
  timeline: { date: string; risk: number | null; level: string }[];
}

export interface InsiderRiskInfo {
  format: string;
  events: number;
  people: number;
  userDays: number;
  trained: boolean;
  timeRange: string[] | null;
  alerts: number;
  reviews: number;
  reviewLevel: number | null;
  alertLevel: number | null;
  lenses: { exfiltration: number; abnormal: number; insider: number };
  falseAlertsPerDay: number | null;
  testCaught: number;
  testOf: number;
  notes: string[];
  queue: InsiderQueueEntry[];
}

// How Auto-detect chose the subtopic (backend app/services/scan_store.py _routing)
export interface AutoDetectInfo {
  subtopicId: string;
  subtopicTitle: string;
  method: string;
  status: string; // "ok" | "fallback"
  reasons: string[];
  secondary: string[];
  note: string;
}

// One trained model's own verdict (backend scan_store._model_details)
export interface ModelDetail {
  name: string;
  level: "high" | "medium" | "low" | string;
  kind: "probability" | "percentile" | string;
  probability: number | null;
  verifyThreshold: number | null;
  alertThreshold: number | null;
  notes: string[];
}

export interface ProvenanceInfo {
  proof: boolean;
  hasContentCredentials: boolean;
  findings: { label: string; detail: string; proof: boolean }[];
}

export interface LiveCheckInfo {
  status: string;
  reason: string;
  finalUrl: string;
  redirectChain: string[];
  page: {
    title: string;
    hasPassword: boolean;
    brandsImitated: string[];
    externalFormTargets: string[];
    sensitiveFields: string[];
  } | null;
}

export interface ResponseAction {
  id: string;
  action: string;
  title: string;
  detail: string;
  priority: "immediate" | "high" | "normal";
  owner: "user" | "soc";
}

// ---- File upload ---------------------------------------------

export interface UploadedFileMeta {
  id: string;
  name: string;
  size: number; // bytes
  type: string;
  progress: number; // 0-100
}

// ---- Dashboard / threat feed -----------------------------------

export interface Threat {
  id: string;
  type: string;
  category: DetectionModuleId;
  severity: Severity;
  target: string;
  riskScore: number;
  status: "active" | "investigating" | "resolved" | "blocked";
  timestamp: string;
}

export interface LiveEvent {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  target: string;
  riskScore: number;
  status: "active" | "investigating" | "resolved" | "blocked";
  timestamp: string;
  category: DetectionModuleId | "network" | "auth" | "api" | "system";
}

export interface ThreatActivityPoint {
  label: string;
  malware: number;
  phishing: number;
  impersonation: number;
  deepfake: number;
  suspiciousUrls: number;
  accountTakeover: number;
  networkThreats: number;
}

export interface ThreatDistributionSlice {
  name: string;
  value: number;
  color: string;
}

export interface SecurityScoreSnapshot {
  score: number;
  status: "PROTECTED" | "AT RISK" | "CRITICAL";
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface ScanHistoryEntry {
  scanId: string;
  target: string;
  targetType: InputKind;
  threatType: string;
  moduleId: DetectionModuleId;
  riskScore: number;
  severity: Severity;
  date: string;
  status: "completed" | "flagged" | "cleared" | "escalated";
  mitre?: string[];
}

export interface NetworkEvent {
  id: string;
  source: string;
  destination: string;
  protocol: string;
  trafficVolume: string;
  threatScore: number;
  status: "normal" | "suspicious" | "blocked";
}

export interface SecurityReport {
  id: string;
  title: string;
  type: string;
  createdAt: string;
  format: "PDF" | "JSON" | "CSV";
  sizeKb: number;
}

export interface LogEntry {
  id: string;
  timestamp: string;
  level: "normal" | "warning" | "critical" | "suspicious";
  source: string;
  message: string;
}

// ---- Authentication -------------------------------------------

export interface AuthUser {
  id: string;
  name: string;
  email: string;
  avatarUrl?: string;
  provider: "password" | "google";
  createdAt: string;
}

export interface SignUpInput {
  name: string;
  email: string;
  password: string;
  turnstileToken?: string;
}

export interface SignInInput {
  email: string;
  password: string;
  rememberMe?: boolean;
  turnstileToken?: string;
}

export interface AuthResult {
  user: AuthUser;
}
