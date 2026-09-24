import type { ReactNode } from "react";
import { cn } from "@/lib/utils";
import { SEVERITY_META, CLASSIFICATION_META } from "@/lib/severity";
import type { Severity, RiskClassification } from "@/types";

export function SeverityBadge({ severity, size = "md" }: { severity: Severity; size?: "sm" | "md" }) {
  const meta = SEVERITY_META[severity];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full font-semibold uppercase tracking-wide border",
        size === "sm" ? "px-2 py-0.5 text-[10px]" : "px-2.5 py-1 text-xs"
      )}
      style={{ color: meta.color, backgroundColor: meta.bg, borderColor: `${meta.color}40` }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: meta.color }} aria-hidden="true" />
      {meta.label}
    </span>
  );
}

export function ClassificationBadge({ classification, size = "md" }: { classification: RiskClassification; size?: "sm" | "md" | "lg" }) {
  const meta = CLASSIFICATION_META[classification];
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md font-bold uppercase tracking-wider border",
        size === "sm" ? "px-2 py-0.5 text-[10px]" : size === "lg" ? "px-4 py-1.5 text-sm" : "px-2.5 py-1 text-xs"
      )}
      style={{ color: meta.color, backgroundColor: meta.bg, borderColor: `${meta.color}50` }}
    >
      {meta.label}
    </span>
  );
}

export function Badge({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-1 rounded-full border border-default bg-elevated px-2 py-0.5 text-[11px] font-medium text-slate-300", className)}>
      {children}
    </span>
  );
}

export function StatusPill({ status }: { status: "normal" | "suspicious" | "blocked" | "active" | "investigating" | "resolved" | "new" }) {
  const map: Record<string, { label: string; color: string; bg: string }> = {
    normal: { label: "Normal", color: "var(--color-safe)", bg: "var(--color-safe-bg)" },
    active: { label: "Active", color: "var(--color-critical)", bg: "var(--color-critical-bg)" },
    new: { label: "New", color: "var(--color-critical)", bg: "var(--color-critical-bg)" },
    suspicious: { label: "Suspicious", color: "var(--color-warning)", bg: "var(--color-warning-bg)" },
    investigating: { label: "Investigating", color: "var(--color-warning)", bg: "var(--color-warning-bg)" },
    blocked: { label: "Blocked", color: "var(--color-critical)", bg: "var(--color-critical-bg)" },
    resolved: { label: "Resolved", color: "var(--color-safe)", bg: "var(--color-safe-bg)" },
  };
  const meta = map[status] ?? map.normal;
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium" style={{ color: meta.color, backgroundColor: meta.bg }}>
      {meta.label}
    </span>
  );
}
