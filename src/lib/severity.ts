import type { RiskClassification, Severity } from "@/types";

export const SEVERITY_META: Record<
  Severity,
  { label: string; color: string; bg: string; border: string }
> = {
  critical: { label: "Critical", color: "var(--color-critical)", bg: "var(--color-critical-bg)", border: "var(--color-critical)" },
  high: { label: "High", color: "var(--color-high)", bg: "var(--color-high-bg)", border: "var(--color-high)" },
  medium: { label: "Medium", color: "var(--color-warning)", bg: "var(--color-warning-bg)", border: "var(--color-warning)" },
  low: { label: "Low", color: "var(--color-safe)", bg: "var(--color-safe-bg)", border: "var(--color-safe)" },
  info: { label: "Info", color: "var(--color-info)", bg: "var(--color-info-bg)", border: "var(--color-info)" },
};

export const CLASSIFICATION_META: Record<
  RiskClassification,
  { label: string; color: string; bg: string; range: string }
> = {
  safe: { label: "SAFE", color: "var(--color-safe)", bg: "var(--color-safe-bg)", range: "0–25" },
  low_risk: { label: "LOW RISK", color: "var(--color-low)", bg: "var(--color-low-bg)", range: "26–50" },
  suspicious: { label: "SUSPICIOUS", color: "var(--color-warning)", bg: "var(--color-warning-bg)", range: "51–70" },
  high_risk: { label: "HIGH RISK", color: "var(--color-high)", bg: "var(--color-high-bg)", range: "71–85" },
  critical: { label: "CRITICAL", color: "var(--color-critical)", bg: "var(--color-critical-bg)", range: "86–100" },
  unverified: { label: "UNABLE TO VERIFY", color: "var(--color-info)", bg: "var(--color-info-bg)", range: "—" },
};

export function classifyRisk(score: number): RiskClassification {
  if (score <= 25) return "safe";
  if (score <= 50) return "low_risk";
  if (score <= 70) return "suspicious";
  if (score <= 85) return "high_risk";
  return "critical";
}

export function severityFromClassification(c: RiskClassification): Severity {
  switch (c) {
    case "safe": return "low";
    case "low_risk": return "low";
    case "suspicious": return "medium";
    case "high_risk": return "high";
    case "critical": return "critical";
    case "unverified": return "info";
  }
}

export function recommendationsFor(c: RiskClassification, threatType: string): string[] {
  switch (c) {
    case "safe":
      return [
        "No immediate action required.",
        "Continue routine monitoring.",
        `No indicators of ${threatType.toLowerCase()} were confirmed.`,
      ];
    case "low_risk":
      return [
        "No urgent action required, but remain cautious.",
        "Re-scan if the source or context changes.",
        "Log this result for historical reference.",
      ];
    case "suspicious":
      return [
        "Review manually before interacting further.",
        "Avoid entering credentials or personal data.",
        "Verify the sender or source through a separate, trusted channel.",
      ];
    case "high_risk":
      return [
        "Avoid interacting, downloading, or installing.",
        "Do not click any embedded links or open attachments.",
        "Report to your security team for further investigation.",
      ];
    case "critical":
      return [
        "Block the source immediately.",
        "Quarantine the affected file, account, or session.",
        "Escalate to the incident response team without delay.",
        "Preserve logs and artifacts for forensic investigation.",
      ];
    case "unverified":
      return [
        "The image could not be read as a QR code.",
        "Retake the photo in good lighting with the code filling the frame.",
      ];
  }
}