// Details the backend already computes for a scan but that were not shown before:
// IOC "seen before" matches, the per-engine breakdown of an email, the email's sender and
// authentication summary, the URL model's own probability, and signals parsed from a login log.
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { ICONS } from "@/lib/icons";
import type { AnalysisResult } from "@/types";

const AUTH_COLOR: Record<string, string> = { pass: "var(--color-safe)", fail: "var(--color-critical)", softfail: "var(--color-warning)" };

function scoreColor(score: number) {
  if (score >= 86) return "var(--color-critical)";
  if (score >= 71) return "var(--color-high)";
  if (score >= 51) return "var(--color-warning)";
  if (score >= 26) return "var(--color-info)";
  return "var(--color-safe)";
}

const SIGNAL_LABELS: Record<string, string> = {
  failedAttempts: "Failed sign-in attempts", sources: "Source IP addresses", distinctFailedUsers: "Different accounts tried",
  successAfterFailures: "Success after failures", impossibleTravel: "Impossible travel", unusualLocation: "Unusual location",
  newDevice: "New device", anonymizingNetwork: "VPN / Tor / proxy", passwordResetRecent: "Recent password reset",
  mfaChanged: "MFA changed", recoveryChanged: "Recovery details changed", privilegeEscalation: "Privilege escalation",
  forwardingRule: "Mail forwarding rule",
};

export function ResultExtras({ result }: { result: AnalysisResult }) {
  const hits = result.iocHits ?? [];
  const engines = (result.engineBreakdown ?? []).filter((e) => e.engine);
  const email = result.emailSummary;
  const model = result.modelAssessment;
  const signals = Object.entries(result.parsedSignals ?? {}).filter(([, v]) => v !== false && v !== 0 && v !== null && v !== "" && typeof v !== "object");

  return (
    <>
      {hits.length > 0 && (
        <Card>
          <CardHeader title="Seen Before" subtitle="Indicators CyberGuard remembered from your earlier risky scans" icon={<ICONS.fingerprint size={16} />} />
          <CardBody className="space-y-2">
            {hits.map((h) => (
              <div key={h.type + h.value} className="flex items-center justify-between gap-3 rounded-lg border border-default bg-elevated p-3">
                <div className="min-w-0">
                  <p className="text-[10px] uppercase tracking-wide text-slate-500">{h.type}</p>
                  <p className="text-sm text-white mono truncate" title={h.value}>{h.value}</p>
                </div>
                <div className="text-right shrink-0">
                  <p className="text-xs text-slate-400">seen {h.timesSeen}×</p>
                  <p className="text-xs font-semibold" style={{ color: scoreColor(h.maxRisk) }}>max risk {h.maxRisk}</p>
                </div>
              </div>
            ))}
          </CardBody>
        </Card>
      )}

      {email && (
        <Card>
          <CardHeader title="Email Details" subtitle="Sender and authentication checks" icon={<ICONS.email size={16} />} />
          <CardBody>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
              <div className="min-w-0">
                <p className="text-[10px] uppercase tracking-wide text-slate-500">From</p>
                <p className="text-white truncate" title={email.from}>{email.displayName ? `${email.displayName} <${email.from}>` : email.from}</p>
              </div>
              <div className="min-w-0">
                <p className="text-[10px] uppercase tracking-wide text-slate-500">Subject</p>
                <p className="text-white truncate" title={email.subject}>{email.subject || "—"}</p>
              </div>
              {email.replyTo && (
                <div className="min-w-0">
                  <p className="text-[10px] uppercase tracking-wide text-slate-500">Reply-To</p>
                  <p className="text-white truncate">{email.replyTo}</p>
                </div>
              )}
              {email.originatingIp && (
                <div>
                  <p className="text-[10px] uppercase tracking-wide text-slate-500">Originating IP</p>
                  <p className="text-white mono">{email.originatingIp}</p>
                </div>
              )}
            </div>
            <div className="flex flex-wrap gap-2 mt-3">
              {(["spf", "dkim", "dmarc"] as const).map((k) => (
                <span key={k} className="rounded-full border px-2.5 py-0.5 text-[11px] font-semibold uppercase"
                      style={{ borderColor: AUTH_COLOR[email[k]] ?? "var(--color-border)", color: AUTH_COLOR[email[k]] ?? "rgb(148 163 184)" }}>
                  {k} {email[k]}
                </span>
              ))}
              <span className="rounded-full border border-default px-2.5 py-0.5 text-[11px] text-slate-400">{email.links} link(s)</span>
              <span className="rounded-full border border-default px-2.5 py-0.5 text-[11px] text-slate-400">{email.attachments} attachment(s)</span>
            </div>
            {email.escalations.length > 0 && (
              <ul className="mt-3 space-y-1">
                {email.escalations.map((e) => (
                  <li key={e} className="text-xs text-red-300 flex gap-1.5"><ICONS.warning size={13} className="shrink-0 mt-0.5" />{e}</li>
                ))}
              </ul>
            )}
          </CardBody>
        </Card>
      )}

      {engines.length > 0 && (
        <Card>
          <CardHeader title="How Each Engine Scored It" subtitle={result.category ? `Final category: ${result.category}` : "Every detector that looked at this item"}
                      icon={<ICONS.layers size={16} />} />
          <CardBody className="space-y-2">
            {engines.map((e) => (
              <div key={e.component + e.engine} className="rounded-lg border border-default bg-elevated p-3">
                <div className="flex items-center justify-between gap-3">
                  <p className="text-sm font-medium text-white capitalize">{e.component}</p>
                  <span className="text-sm font-bold font-mono" style={{ color: scoreColor(e.score) }}>{e.score}</span>
                </div>
                <div className="h-1.5 w-full rounded-full bg-canvas mt-1.5 overflow-hidden">
                  <div className="h-full rounded-full" style={{ width: `${Math.min(100, e.score)}%`, backgroundColor: scoreColor(e.score) }} />
                </div>
                <p className="text-[11px] text-slate-500 mt-1.5">{e.engine}</p>
                {e.explanation && <p className="text-xs text-slate-400 mt-0.5">{e.explanation}</p>}
              </div>
            ))}
          </CardBody>
        </Card>
      )}

      {model && typeof model.site === "string" && typeof model.probability === "number" && (   /* URL model only */
        <Card>
          <CardHeader title="AI Model Assessment" subtitle="Domain-name model trained on PhiUSIIL (235,795 URLs) and the Tranco top-1M list"
                      icon={<ICONS.brain size={16} />} />
          <CardBody>
            <div className="flex flex-wrap items-center gap-6">
              <div>
                <p className="text-[10px] uppercase tracking-wide text-slate-500">Site</p>
                <p className="text-sm text-white mono">{model.site}</p>
              </div>
              <div>
                <p className="text-[10px] uppercase tracking-wide text-slate-500">Phishing probability</p>
                <p className="text-sm font-bold" style={{ color: model.flagged ? "var(--color-critical)" : "var(--color-safe)" }}>
                  {Math.round(model.probability * 100)}%
                </p>
              </div>
              <div>
                <p className="text-[10px] uppercase tracking-wide text-slate-500">Alert threshold</p>
                <p className="text-sm text-white">{Math.round(model.threshold * 100)}%</p>
              </div>
              <div>
                <p className="text-[10px] uppercase tracking-wide text-slate-500">Model verdict</p>
                <p className="text-sm text-white">{model.flagged ? "Looks like a phishing domain" : "Looks like a normal domain"}</p>
              </div>
            </div>
          </CardBody>
        </Card>
      )}

      {signals.length > 0 && (
        <Card>
          <CardHeader title="What Was Read From the Log" subtitle="Signals the account-takeover engine parsed" icon={<ICONS.logs size={16} />} />
          <CardBody>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
              {signals.map(([k, v]) => (
                <div key={k} className="rounded-lg border border-default bg-elevated p-2.5">
                  <p className="text-[10px] uppercase tracking-wide text-slate-500">{SIGNAL_LABELS[k] ?? k}</p>
                  <p className="text-sm font-semibold text-white">{v === true ? "Yes" : String(v)}</p>
                </div>
              ))}
            </div>
          </CardBody>
        </Card>
      )}
    </>
  );
}
