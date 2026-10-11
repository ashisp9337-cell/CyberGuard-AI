import type { DetectionModule, DetectionModuleId, IndicatorTemplate, InputKind, SubtopicConfig } from "@/types";

// Reusable indicator template groups, mixed per subtopic
const phishingIndicators: IndicatorTemplate[] = [
  { label: "Urgency language detected", description: "Message pressures the recipient to act immediately ('act now', 'account will be suspended').", severity: "high", weight: 18 },
  { label: "Sender domain mismatch", description: "Display name does not match the underlying sender domain.", severity: "high", weight: 20 },
  { label: "Credential request", description: "Content asks the recipient to enter a password, OTP, or PIN.", severity: "critical", weight: 25 },
  { label: "Suspicious embedded link", description: "Link text does not match its underlying destination URL.", severity: "high", weight: 20 },
  { label: "Brand impersonation cues", description: "Uses logos, colors, or language mimicking a trusted brand.", severity: "medium", weight: 12 },
  { label: "Poor grammar / spelling anomalies", description: "Contains inconsistencies typical of templated scam content.", severity: "low", weight: 6 },
  { label: "Suspicious attachment", description: "Attachment type is commonly used to deliver malware.", severity: "critical", weight: 22 },
  { label: "Generic greeting", description: "Message lacks personalization typical of legitimate correspondence.", severity: "low", weight: 5 },
];

const urlIndicators: IndicatorTemplate[] = [
  { label: "Look-alike domain", description: "Domain closely resembles a well-known brand using character substitution.", severity: "critical", weight: 24 },
  { label: "Recently registered domain", description: "Domain was registered within the last 30 days.", severity: "high", weight: 16 },
  { label: "No valid SSL certificate", description: "Connection is not secured with a valid, trusted certificate.", severity: "high", weight: 15 },
  { label: "Suspicious redirect chain", description: "URL passes through multiple unrelated domains before resolving.", severity: "high", weight: 18 },
  { label: "Fake login form detected", description: "Page structure mimics a legitimate authentication form.", severity: "critical", weight: 22 },
  { label: "Low domain reputation score", description: "Domain has been previously flagged by threat intelligence feeds.", severity: "medium", weight: 12 },
  { label: "URL contains obfuscated characters", description: "Uses encoding or homoglyphs to disguise the true destination.", severity: "medium", weight: 10 },
];

const deepfakeIndicators: IndicatorTemplate[] = [
  { label: "Facial boundary artifacts", description: "Inconsistent blending detected around facial edges.", severity: "high", weight: 20 },
  { label: "Unnatural blink pattern", description: "Eye blink frequency deviates from natural human baseline.", severity: "medium", weight: 14 },
  { label: "Audio-visual desync", description: "Lip movement does not align precisely with audio track.", severity: "high", weight: 18 },
  { label: "Inconsistent lighting/shadows", description: "Lighting on the subject doesn't match the scene's light sources.", severity: "medium", weight: 12 },
  { label: "GAN fingerprint detected", description: "Frequency-domain analysis reveals patterns typical of generative models.", severity: "critical", weight: 24 },
  { label: "Voice cloning artifacts", description: "Spectral irregularities consistent with synthetic voice generation.", severity: "high", weight: 18 },
  { label: "Metadata inconsistency", description: "File metadata shows signs of editing software not disclosed by source.", severity: "low", weight: 8 },
];

const impersonationIndicators: IndicatorTemplate[] = [
  { label: "Authority impersonation language", description: "Message invokes an authority figure to pressure compliance.", severity: "high", weight: 20 },
  { label: "Unverified contact channel", description: "Communication originates from a channel not officially registered.", severity: "high", weight: 18 },
  { label: "Mismatched organizational details", description: "Claimed affiliation doesn't match verifiable public records.", severity: "medium", weight: 14 },
  { label: "Request for sensitive action", description: "Asks for funds transfer, credentials, or confidential data.", severity: "critical", weight: 25 },
  { label: "Profile recently created", description: "The impersonating account or profile was created very recently.", severity: "medium", weight: 12 },
  { label: "Inconsistent writing style", description: "Tone and style differ from the known contact's historical pattern.", severity: "low", weight: 7 },
];

const credentialIndicators: IndicatorTemplate[] = [
  { label: "Multiple failed login attempts", description: "Threshold of failed authentication attempts exceeded in a short window.", severity: "high", weight: 18 },
  { label: "Impossible travel detected", description: "Login locations are geographically implausible within the time elapsed.", severity: "critical", weight: 24 },
  { label: "Unrecognized device fingerprint", description: "Device signature does not match any previously trusted device.", severity: "high", weight: 18 },
  { label: "Password spray pattern", description: "Single password attempted across many accounts in short succession.", severity: "critical", weight: 22 },
  { label: "Unusual session behavior", description: "Session activity deviates from the account's established baseline.", severity: "medium", weight: 12 },
  { label: "Sudden privilege escalation", description: "Account permissions changed shortly after suspicious login.", severity: "critical", weight: 20 },
  { label: "Login from anonymizing network", description: "Connection originates from a known VPN/Tor exit node.", severity: "medium", weight: 10 },
];

const cyberThreatIndicators: IndicatorTemplate[] = [
  { label: "Known malware signature match", description: "File hash matches a signature in threat intelligence databases.", severity: "critical", weight: 28 },
  { label: "Suspicious process behavior", description: "Executable attempts to modify system-critical files or registry keys.", severity: "critical", weight: 22 },
  { label: "Obfuscated / packed code", description: "Binary shows signs of packing commonly used to evade detection.", severity: "high", weight: 16 },
  { label: "Anomalous outbound traffic", description: "Connection to a rare or previously unseen external endpoint.", severity: "high", weight: 16 },
  { label: "Excessive API request rate", description: "Request volume from a single client far exceeds normal baseline.", severity: "medium", weight: 12 },
  { label: "Large unscheduled data transfer", description: "Significant data volume moved outside typical business hours.", severity: "high", weight: 18 },
  { label: "Privilege misuse pattern", description: "Account accessed resources outside its normal scope of work.", severity: "medium", weight: 12 },
  { label: "Sandbox evasion technique", description: "Sample includes logic to detect and evade analysis environments.", severity: "high", weight: 16 },
];

export const DETECTION_MODULES: DetectionModule[] = [
  {
    id: "phishing",
    name: "AI-Powered Phishing Detection",
    shortName: "Phishing Detection",
    description: "Detect phishing attempts across email, SMS, social media, QR codes, and fraudulent websites using AI-driven linguistic and structural analysis.",
    icon: "email",
    color: "#f97316",
    subtopics: [
      { id: "email-analysis", moduleId: "phishing", title: "Email Analysis", description: "Analyze email content, headers, and attachments for phishing indicators.", icon: "email", inputKind: "email", supportedInput: "Paste raw email or .eml file", acceptedFileTypes: [".eml", ".msg", ".txt"], maxFileSizeMb: 10, placeholder: "Paste the full email content here, including headers if available...", indicatorPool: phishingIndicators, extraFields: [{ id: "sender", label: "Sender email address", placeholder: "e.g. security@paypa1-support.com" }] },
      { id: "sms-analysis", moduleId: "phishing", title: "SMS / Message Analysis", description: "Scan text messages for scam keywords, urgency cues, and malicious links.", icon: "message", inputKind: "text", supportedInput: "Paste message text", placeholder: "Paste the suspicious SMS or message text here...", indicatorPool: phishingIndicators },
      { id: "social-media-analysis", moduleId: "phishing", title: "Social Media Message Analysis", description: "Analyze DMs and comments from Instagram, Facebook, X, and LinkedIn.", icon: "message", inputKind: "text", supportedInput: "Paste message text", placeholder: "Paste the social media message content here...", indicatorPool: phishingIndicators, extraFields: [{ id: "platform", label: "Platform", placeholder: "e.g. Instagram, LinkedIn" }] },
      { id: "qr-phishing", moduleId: "phishing", title: "QR Code Phishing Detection", description: "Upload a QR code image to decode and evaluate the destination URL.", icon: "qrcode", inputKind: "file", supportedInput: "Upload QR code image", acceptedFileTypes: [".png", ".jpg", ".jpeg"], maxFileSizeMb: 5, indicatorPool: urlIndicators },
      { id: "fraudulent-website", moduleId: "phishing", title: "Fraudulent Website Detection", description: "Detect fake login pages and brand impersonation in website screenshots or URLs.", icon: "url", inputKind: "url", supportedInput: "Enter website URL or upload screenshot", placeholder: "https://example.com/login", indicatorPool: [...urlIndicators.slice(0, 4), phishingIndicators[4]] },
      { id: "malicious-url", moduleId: "phishing", title: "Malicious URL Analysis", description: "Evaluate domain reputation, redirects, and SSL characteristics.", icon: "url", inputKind: "url", supportedInput: "Enter a URL to analyze", placeholder: "https://example.com", indicatorPool: urlIndicators },
    ],
  },
  {
    id: "deepfake",
    name: "Deepfake Detection",
    shortName: "Deepfake Detection",
    description: "Identify AI-generated or manipulated images, video, and audio using forensic and generative-model fingerprinting.",
    icon: "video",
    color: "#a855f7",
    subtopics: [
      { id: "image-analysis", moduleId: "deepfake", title: "Image Analysis", description: "Detect manipulated or AI-generated images.", icon: "image", inputKind: "file", supportedInput: "Upload image file", acceptedFileTypes: [".png", ".jpg", ".jpeg", ".webp"], maxFileSizeMb: 20, indicatorPool: deepfakeIndicators.filter((i) => !i.label.toLowerCase().includes("audio") && !i.label.toLowerCase().includes("voice")) },
      { id: "video-analysis", moduleId: "deepfake", title: "Video Analysis", description: "Detect facial re-enactment, face-swap, and synthetic video artifacts.", icon: "video", inputKind: "file", supportedInput: "Upload video file", acceptedFileTypes: [".mp4", ".mov", ".avi"], maxFileSizeMb: 200, indicatorPool: deepfakeIndicators },
      { id: "audio-analysis", moduleId: "deepfake", title: "Voice & Audio Analysis", description: "Detect synthetic and cloned voice audio.", icon: "audio", inputKind: "file", supportedInput: "Upload audio file", acceptedFileTypes: [".mp3", ".wav", ".aac"], maxFileSizeMb: 50, indicatorPool: [deepfakeIndicators[5], deepfakeIndicators[4], deepfakeIndicators[6]] },
      { id: "ai-multimedia", moduleId: "deepfake", title: "AI-Generated Multimedia Detection", description: "General-purpose detection across mixed multimedia content.", icon: "multimedia", inputKind: "file", supportedInput: "Upload image, video, or audio file", acceptedFileTypes: [".png", ".jpg", ".mp4", ".mp3", ".wav"], maxFileSizeMb: 200, indicatorPool: deepfakeIndicators },
    ],
  },
  {
    id: "impersonation",
    name: "Digital Impersonation Detection",
    shortName: "Impersonation Detection",
    description: "Identify impersonation of officials, executives, institutions, and known contacts across digital channels.",
    icon: "impersonation",
    color: "#eab308",
    subtopics: [
      { id: "government-impersonation", moduleId: "impersonation", title: "Government Official Impersonation", description: "Detect fraudulent claims of government authority.", icon: "government", inputKind: "identity", supportedInput: "Paste message, name, or profile details", placeholder: "Describe or paste the communication claiming government authority...", indicatorPool: impersonationIndicators, extraFields: [{ id: "senderEmail", label: "Sender email (optional)", placeholder: "e.g. noreply@passport.gov.in" }] },
      { id: "management-impersonation", moduleId: "impersonation", title: "Senior Management Impersonation", description: "Detect CEO/executive fraud and business email compromise attempts.", icon: "management", inputKind: "identity", supportedInput: "Paste message or executive details", placeholder: "Paste the message claiming to be from senior management...", indicatorPool: impersonationIndicators, extraFields: [{ id: "companyDomain", label: "Your company's domain (optional)", placeholder: "e.g. acme.com" }, { id: "senderEmail", label: "Sender email (optional)", placeholder: "e.g. ceo@acme.com" }] },
      { id: "teacher-impersonation", moduleId: "impersonation", title: "Teacher / University Authority Impersonation", description: "Detect impersonation of academic staff or institutions.", icon: "teacher", inputKind: "identity", supportedInput: "Paste message or profile details", placeholder: "Paste the communication claiming academic authority...", indicatorPool: impersonationIndicators, extraFields: [{ id: "institutionDomain", label: "Your institution's domain (optional)", placeholder: "e.g. bput.ac.in" }, { id: "senderEmail", label: "Sender email (optional)", placeholder: "e.g. registrar@bput.ac.in" }] },
      { id: "financial-impersonation", moduleId: "impersonation", title: "Financial Institution Impersonation", description: "Detect fake bank, NBFC, or payment provider communications.", icon: "financial", inputKind: "identity", supportedInput: "Paste message or institution details", placeholder: "Paste the communication claiming to be from a financial institution...", indicatorPool: impersonationIndicators, extraFields: [{ id: "senderEmail", label: "Sender email (optional)", placeholder: "e.g. alerts@hdfcbank.com" }] },
      { id: "brand-impersonation", moduleId: "impersonation", title: "Organization / Brand Impersonation", description: "Detect fake accounts or content impersonating a company or brand.", icon: "financial", inputKind: "identity", supportedInput: "Paste profile or message details", placeholder: "Paste the profile or message details claiming brand affiliation...", indicatorPool: impersonationIndicators, extraFields: [{ id: "senderEmail", label: "Sender email / handle (optional)", placeholder: "e.g. alerts@amazon.com" }] },
      { id: "contact-impersonation", moduleId: "impersonation", title: "Friend / Relative / Known Contact Impersonation", description: "Detect account takeover or spoofing of known personal contacts.", icon: "contact", inputKind: "identity", supportedInput: "Paste message or contact details", placeholder: "Paste the suspicious message from a supposed known contact...", indicatorPool: impersonationIndicators, extraFields: [{ id: "claimedSenderName", label: "Claimed sender (must match a saved contact)", placeholder: "e.g. Dr. S. K. Nayak (HOD)" }, { id: "senderEmail", label: "Sender email / handle (optional)", placeholder: "e.g. sender@example.com" }] },
    ],
  },
  {
    id: "credential",
    name: "Credential Theft & Account Takeover Detection",
    shortName: "Credential Security",
    description: "Behavioral analytics for login anomalies, session hijacking, and account takeover risk.",
    icon: "credential",
    color: "#38bdf8",
    subtopics: [
      { id: "failed-logins", moduleId: "credential", title: "Multiple Failed Login Attempts", description: "Detect brute-force login patterns against a single account.", icon: "login", inputKind: "identity", supportedInput: "Enter account identifier or paste login log", placeholder: "Enter username/email or paste login attempt logs...", indicatorPool: credentialIndicators },
      { id: "password-spraying", moduleId: "credential", title: "Password Spraying Detection", description: "Detect low-and-slow password attacks across many accounts.", icon: "credential", inputKind: "text", supportedInput: "Paste authentication log excerpt", placeholder: "Paste authentication log lines here...", indicatorPool: credentialIndicators },
      { id: "unusual-location", moduleId: "credential", title: "Unusual Location Login", description: "Detect logins from atypical or impossible-travel locations.", icon: "location", inputKind: "identity", supportedInput: "Enter account and location details", placeholder: "Describe the login location and account context...", indicatorPool: credentialIndicators },
      { id: "unknown-device", moduleId: "credential", title: "Unknown Device Detection", description: "Detect access from previously untrusted devices.", icon: "device", inputKind: "identity", supportedInput: "Enter device fingerprint or session details", placeholder: "Paste device/session details...", indicatorPool: credentialIndicators },
      { id: "session-activity", moduleId: "credential", title: "Suspicious Session Activity", description: "Detect anomalous in-session behavior after authentication.", icon: "session", inputKind: "text", supportedInput: "Paste session activity log", placeholder: "Paste session activity log...", indicatorPool: credentialIndicators },
      { id: "behavior-changes", moduleId: "credential", title: "Sudden Account Behavior Changes", description: "Detect abrupt deviations from an account's behavioral baseline.", icon: "behavior", inputKind: "text", supportedInput: "Describe or paste recent account activity", placeholder: "Describe the recent account behavior change...", indicatorPool: credentialIndicators },
    ],
  },
  {
    id: "url-security",
    name: "Malicious URL & Website Detection",
    shortName: "URL Security",
    description: "Deep domain, redirect, and SSL analysis to identify spoofed and malicious websites.",
    icon: "url",
    color: "#22c55e",
    subtopics: [
      { id: "domain-spoofing", moduleId: "url-security", title: "Domain Spoofing Detection", description: "Detect domains impersonating trusted brands.", icon: "url", inputKind: "url", supportedInput: "Enter website URL", placeholder: "https://example.com", indicatorPool: urlIndicators },
      { id: "lookalike-domain", moduleId: "url-security", title: "Look-Alike Domain Detection", description: "Detect character-substitution and typosquatting domains.", icon: "url", inputKind: "url", supportedInput: "Enter website URL", placeholder: "https://examp1e.com", indicatorPool: urlIndicators },
      { id: "url-manipulation", moduleId: "url-security", title: "URL Manipulation Detection", description: "Detect obfuscated, encoded, or manipulated URL structures.", icon: "url", inputKind: "url", supportedInput: "Enter website URL", placeholder: "https://example.com/%2e%2e/login", indicatorPool: urlIndicators },
      { id: "redirect-analysis", moduleId: "url-security", title: "Redirect Analysis", description: "Trace and evaluate multi-hop redirect chains.", icon: "url", inputKind: "url", supportedInput: "Enter starting URL", placeholder: "https://example.com/go?to=...", indicatorPool: urlIndicators },
      { id: "ssl-domain-analysis", moduleId: "url-security", title: "SSL & Domain Analysis", description: "Evaluate certificate validity and domain registration age.", icon: "url", inputKind: "url", supportedInput: "Enter website URL", placeholder: "https://example.com", indicatorPool: urlIndicators },
      { id: "fake-login-page", moduleId: "url-security", title: "Fake Login Page Detection", description: "Detect credential-harvesting login page clones.", icon: "url", inputKind: "url", supportedInput: "Enter URL or upload screenshot", placeholder: "https://example.com/login", indicatorPool: urlIndicators },
    ],
  },
  {
    id: "cyber-threat",
    name: "Intelligent Cyber Threat Detection",
    shortName: "Cyber Threat Detection",
    description: "Malware analysis, network monitoring, API abuse, exfiltration, and insider threat detection.",
    icon: "malware",
    color: "#ef4444",
    subtopics: [
      { id: "malware-detection", moduleId: "cyber-threat", title: "Malware Detection", description: "Static and behavioral analysis of uploaded files and applications.", icon: "malware", inputKind: "file", supportedInput: "Upload file or application", acceptedFileTypes: [".exe", ".apk", ".dll", ".pdf", ".docx", ".zip"], maxFileSizeMb: 100, indicatorPool: cyberThreatIndicators },
      { id: "network-traffic", moduleId: "cyber-threat", title: "Suspicious Network Traffic Detection", description: "Monitor and analyze network flows for anomalous patterns.", icon: "network", inputKind: "text", supportedInput: "Paste network log or flow data", placeholder: "Paste network traffic log or flow records...", indicatorPool: cyberThreatIndicators },
      { id: "api-abuse", moduleId: "cyber-threat", title: "API Abuse Detection", description: "Detect excessive requests, token abuse, and suspicious endpoint usage.", icon: "api", inputKind: "text", supportedInput: "Paste API access log", placeholder: "Paste API access log entries...", indicatorPool: cyberThreatIndicators },
      { id: "data-exfiltration", moduleId: "cyber-threat", title: "Data Exfiltration Detection", description: "Detect unusual uploads and large sensitive data transfers.", icon: "exfiltration", inputKind: "text", supportedInput: "Paste transfer log or describe activity", placeholder: "Describe or paste the data transfer activity...", indicatorPool: cyberThreatIndicators },
      { id: "abnormal-activity", moduleId: "cyber-threat", title: "Abnormal User Activity Detection", description: "Compare current behavior against an established baseline.", icon: "behavior", inputKind: "text", supportedInput: "Describe or paste activity log", placeholder: "Describe the current vs normal user activity...", indicatorPool: cyberThreatIndicators },
      { id: "insider-threat", moduleId: "cyber-threat", title: "Insider Threat Detection", description: "Detect unauthorized access and abnormal internal data handling.", icon: "insider", inputKind: "text", supportedInput: "Describe or paste access activity", placeholder: "Describe the internal access or file activity...", indicatorPool: cyberThreatIndicators },
      { id: "log-analysis", moduleId: "cyber-threat", title: "System & Application Log Analysis", description: "Upload or paste logs for automated anomaly highlighting.", icon: "logs", inputKind: "text", supportedInput: "Paste logs or upload log file", acceptedFileTypes: [".txt", ".log", ".json", ".csv"], maxFileSizeMb: 25, placeholder: "Paste system or application log lines here...", indicatorPool: cyberThreatIndicators },
    ],
  },
];

export function getModule(id: string): DetectionModule | undefined {
  return DETECTION_MODULES.find((m) => m.id === id);
}

/**
 * "Auto-detect" entry for each module: the backend classifies the input
 * (subtopicId "auto") and routes it to the existing detector for the detected
 * subtopic. File types listed here are ones the backend upload accepts AND the
 * routed detector actually reads.
 */
const AUTO_INPUT: Record<DetectionModuleId, { inputKind: InputKind; acceptedFileTypes?: string[]; supportedInput: string; placeholder: string }> = {
  phishing: { inputKind: "text", acceptedFileTypes: [".eml", ".msg", ".txt", ".png", ".jpg", ".jpeg"],
    supportedInput: "Paste an email, SMS, social-media message or URL, or upload an .eml file / QR image",
    placeholder: "Paste the full email (with headers), a message, or a URL..." },
  deepfake: { inputKind: "file", acceptedFileTypes: [".png", ".jpg", ".jpeg", ".mp4", ".mov", ".avi", ".mkv", ".webm", ".mp3", ".wav"],
    supportedInput: "Upload an image, video or audio file", placeholder: "" },
  impersonation: { inputKind: "text", supportedInput: "Paste the message that claims to come from someone",
    placeholder: "Paste the message (an email with headers works best)..." },
  credential: { inputKind: "text", supportedInput: "Paste authentication or session log lines",
    placeholder: "Paste login / session log lines here..." },
  "url-security": { inputKind: "url", supportedInput: "Enter a URL or website address", placeholder: "https://example.com/login" },
  "cyber-threat": { inputKind: "text", supportedInput: "Paste log or event lines (firewall, API, process, audit, system)",
    placeholder: "Paste raw log or event lines here..." },
};

export function getAutoSubtopic(mod: DetectionModule): SubtopicConfig {
  const cfg = AUTO_INPUT[mod.id];
  return {
    id: "auto", moduleId: mod.id, title: "Auto-detect",
    description: "CYBERGUARD identifies the detection type from the input and runs the matching detector.",
    icon: mod.icon, inputKind: cfg.inputKind, supportedInput: cfg.supportedInput, placeholder: cfg.placeholder,
    acceptedFileTypes: cfg.acceptedFileTypes, maxFileSizeMb: 15, indicatorPool: mod.subtopics[0]?.indicatorPool ?? [],
  };
}

export function getSubtopic(moduleId: string, subtopicId: string) {
  const mod = getModule(moduleId);
  if (mod && subtopicId === "auto") return getAutoSubtopic(mod);
  return mod?.subtopics.find((s) => s.id === subtopicId);
}

export function findSubtopicGlobal(subtopicId: string) {
  for (const mod of DETECTION_MODULES) {
    const s = mod.subtopics.find((s) => s.id === subtopicId);
    if (s) return { module: mod, subtopic: s };
  }
  return undefined;
}
