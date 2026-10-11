import { useState } from "react";
import { motion } from "framer-motion";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { ClassificationBadge, SeverityBadge } from "@/components/ui/Badge";
import { CircularScore } from "@/components/ui/Progress";
import { Button } from "@/components/ui/Button";
import { CLASSIFICATION_META } from "@/lib/severity";
import { formatDate } from "@/lib/utils";
import { ICONS } from "@/lib/icons";
import type { AnalysisResult, ResponseAction } from "@/types";
import { useToast } from "@/context/ToastContext";
import { escalateScan } from "@/services/api/incidentsService";

const PRIORITY_META: Record<ResponseAction["priority"], { label: string; color: string; bg: string }> = {
  immediate: { label: "Now", color: "var(--color-critical)", bg: "var(--color-critical-bg)" },
  high: { label: "Soon", color: "var(--color-high)", bg: "var(--color-high-bg)" },
  normal: { label: "Later", color: "var(--color-info)", bg: "var(--color-info-bg)" },
};

export function ResultView({ result, onNewScan, onSave }: { result: AnalysisResult; onNewScan: () => void; onSave?: () => void }) {
  const { notify } = useToast();
  const [escalation, setEscalation] = useState<"idle" | "sending" | "done">("idle");

  async function handleEscalate() {
    setEscalation("sending");
    try {
      const res = await escalateScan(result.scanId);
      setEscalation("done");
      notify({
        variant: "success",
        title: "Escalated to the security team",
        description: res.alertChannels.length
          ? `Incident opened and an alert is being sent via ${res.alertChannels.join(", ")}.`
          : "Incident opened on the dashboard. (No Telegram/email alert channel is configured.)",
      });
    } catch (err) {
      setEscalation("idle");
      notify({ variant: "critical", title: "Could not escalate", description: err instanceof Error ? err.message : "Please try again." });
    }
  }
  const meta = CLASSIFICATION_META[result.classification];
  const triggered = result.indicators.filter((i) => i.triggered).sort((a, b) => b.weight - a.weight);

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="space-y-5">
      {/* Risk score header */}
      <Card className="overflow-hidden">
        <div className="p-6 flex flex-col md:flex-row items-center md:items-start gap-6" style={{ background: `linear-gradient(135deg, ${meta.bg} 0%, transparent 60%)` }}>
          <CircularScore value={result.riskScore} size={140} strokeWidth={12} label="RISK SCORE" color={meta.color} />
          <div className="flex-1 text-center md:text-left">
            <div className="flex flex-wrap items-center justify-center md:justify-start gap-2 mb-2">
              <ClassificationBadge classification={result.classification} size="lg" />
              <SeverityBadge severity={result.severity} />
            </div>
            <h2 className="text-lg font-bold text-white">{result.threatType}</h2>
            <p className="text-sm text-slate-400 mt-1 mono truncate max-w-lg mx-auto md:mx-0">{result.target}</p>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4 text-left">
              <div>
                <p className="text-[10px] uppercase tracking-wide text-slate-500">Confidence</p>
                <p className="text-sm font-semibold text-white mt-0.5">{result.confidenceScore}%</p>
              </div>
              <div>
                <p className="text-[10px] uppercase tracking-wide text-slate-500">Scan ID</p>
                <p className="text-sm font-semibold text-white mt-0.5 mono truncate" title={result.scanId}>{result.scanId}</p>
              </div>
              <div>
                <p className="text-[10px] uppercase tracking-wide text-slate-500">Detected</p>
                <p className="text-sm font-semibold text-white mt-0.5">{formatDate(result.detectionTime)}</p>
              </div>
              <div>
                <p className="text-[10px] uppercase tracking-wide text-slate-500">Engine</p>
                <p className="text-sm font-semibold text-white mt-0.5 truncate">{result.analysisEngine}</p>
              </div>
            </div>
          </div>
        </div>
      </Card>

      {/* Explainable AI */}
      <Card>
        <CardHeader title="Why Was This Flagged?" subtitle="Explainable AI reasoning" icon={<ICONS.cpu size={16} />} />
        <CardBody>
          <p className="text-sm text-slate-300 leading-relaxed">{result.explanation}</p>
        </CardBody>
      </Card>

      {/* Indicators */}
      <Card>
        <CardHeader title="Detected Indicators" subtitle={`${triggered.length} of ${result.indicators.length} checks triggered`} icon={<ICONS.fileWarning size={16} />} />
        <CardBody className="space-y-2">
          {triggered.length === 0 && (
            <p className="text-sm text-slate-500 py-4 text-center">No suspicious indicators were triggered during this analysis.</p>
          )}
          {triggered.map((ind) => (
            <div key={ind.id} className="flex items-start gap-3 rounded-lg border border-default bg-elevated p-3">
              <SeverityBadge severity={ind.severity} size="sm" />
              <div className="min-w-0">
                <p className="text-sm font-medium text-white">{ind.label}</p>
                <p className="text-xs text-slate-500 mt-0.5">{ind.description}</p>
              </div>
            </div>
          ))}
        </CardBody>
      </Card>

      {/* Auto-quarantine banner */}
      {result.quarantine?.status === "quarantined" && (
        <div className="flex items-start gap-3 rounded-xl border p-4"
             style={{ borderColor: "var(--color-critical)", backgroundColor: "var(--color-critical-bg)" }}>
          <ICONS.lock size={18} className="mt-0.5 shrink-0" style={{ color: "var(--color-critical)" }} />
          <div>
            <p className="text-sm font-semibold text-white">This email was quarantined automatically</p>
            <p className="text-xs text-slate-400 mt-0.5">{result.quarantine.reason}. You can release or delete it from Email Quarantine on the dashboard.</p>
          </div>
        </div>
      )}

      {/* Recommendations */}
      <Card>
        <CardHeader
          title="Recommended Actions"
          subtitle={result.responseActions?.length ? "Chosen for this specific threat, most urgent first" : undefined}
          icon={<ICONS.shieldCheck size={16} />}
        />
        <CardBody>
          {result.responseActions?.length ? (
            <ul className="space-y-2">
              {result.responseActions.map((a) => (
                <li key={a.id} className="flex items-start gap-3 rounded-lg border border-default bg-elevated p-3">
                  <span
                    className="shrink-0 rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide"
                    style={{ color: PRIORITY_META[a.priority].color, backgroundColor: PRIORITY_META[a.priority].bg }}
                  >
                    {PRIORITY_META[a.priority].label}
                  </span>
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium text-white">{a.title}</p>
                    <p className="text-xs text-slate-500 mt-0.5">{a.detail}</p>
                  </div>
                  <span className="shrink-0 text-[10px] text-slate-500 mt-0.5">{a.owner === "soc" ? "Security team" : "User"}</span>
                </li>
              ))}
            </ul>
          ) : (
            <ul className="space-y-2.5">
              {result.recommendations.map((r, i) => (
                <li key={i} className="flex items-start gap-2.5 text-sm text-slate-300">
                  <ICONS.chevronRight size={15} className="text-cyan-400 mt-0.5 shrink-0" />
                  {r}
                </li>
              ))}
            </ul>
          )}
        </CardBody>
      </Card>

      <div className="flex flex-wrap gap-3">
        <Button variant="primary" onClick={onNewScan}>
          <ICONS.scan size={15} /> Run Another Scan
        </Button>
        <Button variant="secondary" onClick={onSave}>
          <ICONS.download size={15} /> Export Report
        </Button>
        <Button variant="ghost" onClick={handleEscalate} disabled={escalation !== "idle"}>
          <ICONS.send size={15} />{" "}
          {escalation === "done" ? "Escalated to Team ✓" : escalation === "sending" ? "Escalating…" : "Escalate to Team"}
        </Button>
      </div>
    </motion.div>
  );
}
