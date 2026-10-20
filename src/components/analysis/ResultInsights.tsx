// Details the backend computes for every scan but that were not shown before:
//  * Auto-detect: which subtopic was chosen and why
//  * every trained model that looked at the item, with its own verdict and alert levels
//  * image provenance ("Made with AI" labels / generator settings found in the file)
//  * the read-only link check: every redirect hop and what the final page asks for
//  * for an unclear impersonation message: the score of every detector that ran
// Everything here comes from GET/POST responses that are already the user's own scan data.
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { ICONS } from "@/lib/icons";
import type { AnalysisResult, ModelDetail } from "@/types";

const LEVEL_META: Record<string, { label: string; color: string }> = {
  high: { label: "Alert", color: "var(--color-critical)" },
  medium: { label: "Verify", color: "var(--color-warning)" },
  low: { label: "Below warning level", color: "var(--color-safe)" },
};

/** 0.79 -> "79%", 0.99999769 -> "99.9998%" (levels this close to 100% must not be rounded up to 100%). */
function pct(x: number | null | undefined): string {
  if (x === null || x === undefined || Number.isNaN(x)) return "—";
  if (x >= 0.995 && x < 1) {
    let s = (x * 100).toFixed(4);
    for (let d = 5; d <= 10 && s.startsWith("100"); d++) s = (x * 100).toFixed(d);
    return `${s.replace(/0+$/, "").replace(/\.$/, "")}%`;
  }
  return `${Math.round(x * 100)}%`;
}

function scoreColor(score: number) {
  if (score >= 86) return "var(--color-critical)";
  if (score >= 71) return "var(--color-high)";
  if (score >= 51) return "var(--color-warning)";
  if (score >= 26) return "var(--color-info)";
  return "var(--color-safe)";
}

function Label({ children }: { children: string }) {
  return <p className="text-[10px] uppercase tracking-wide text-slate-500">{children}</p>;
}

function ModelRow({ m }: { m: ModelDetail }) {
  const meta = LEVEL_META[m.level] ?? LEVEL_META.low;
  const isPercentile = m.kind === "percentile";
  return (
    <div className="rounded-lg border border-default bg-elevated p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm font-medium text-white">{m.name}</p>
        <span className="rounded-full border px-2.5 py-0.5 text-[11px] font-semibold"
              style={{ borderColor: meta.color, color: meta.color }}>{meta.label}</span>
      </div>
      <div className="mt-2 grid grid-cols-3 gap-3 text-sm">
        <div>
          <Label>{isPercentile ? "Risk percentile" : "Model score"}</Label>
          <p className="font-semibold" style={{ color: meta.color }}>{pct(m.probability)}</p>
        </div>
        <div>
          <Label>Verify from</Label>
          <p className="text-white">{pct(m.verifyThreshold)}</p>
        </div>
        <div>
          <Label>Alert from</Label>
          <p className="text-white">{pct(m.alertThreshold)}</p>
        </div>
      </div>
      {m.notes.length > 0 && (
        <ul className="mt-2 space-y-0.5">
          {m.notes.map((n) => <li key={n} className="text-xs text-slate-400">• {n}</li>)}
        </ul>
      )}
    </div>
  );
}

export function ResultInsights({ result }: { result: AnalysisResult }) {
  const auto = result.autoDetect;
  const models = result.modelDetails ?? [];
  const prov = result.provenance;
  const live = result.liveCheck;
  const checked = result.checkedDetectors ?? [];

  return (
    <>
      {auto && auto.subtopicId && (
        <Card>
          <CardHeader title="How Auto-Detect Chose This Check"
                      subtitle={auto.status === "fallback"
                        ? "The category was unclear, so every detector of this module checked the input"
                        : `Sent to: ${auto.subtopicTitle}`}
                      icon={<ICONS.target size={16} />} />
          <CardBody>
            {auto.reasons.length > 0 && (
              <ul className="space-y-1">
                {auto.reasons.map((r) => (
                  <li key={r} className="text-sm text-slate-300 flex gap-1.5">
                    <ICONS.success size={14} className="shrink-0 mt-0.5" style={{ color: "var(--color-info)" }} />{r}
                  </li>
                ))}
              </ul>
            )}
            {auto.secondary.length > 0 && (
              <p className="text-xs text-slate-500 mt-2">Also considered: {auto.secondary.join(", ")}</p>
            )}
            {auto.note && <p className="text-xs text-slate-500 mt-1">{auto.note}</p>}
          </CardBody>
        </Card>
      )}

      {checked.length > 0 && (
        <Card>
          <CardHeader title="Every Detector That Checked It" subtitle="The strongest verdict is the one shown above"
                      icon={<ICONS.layers size={16} />} />
          <CardBody className="space-y-2">
            {[...checked].sort((a, b) => b.riskScore - a.riskScore).map((d) => (
              <div key={d.detector} className="flex items-center gap-3">
                <p className="text-sm text-white w-36 sm:w-56 shrink-0 truncate" title={d.detector}>{d.detector}</p>
                <div className="h-1.5 flex-1 rounded-full bg-canvas overflow-hidden">
                  <div className="h-full rounded-full" style={{ width: `${Math.min(100, d.riskScore)}%`, backgroundColor: scoreColor(d.riskScore) }} />
                </div>
                <span className="text-sm font-bold font-mono w-8 text-right" style={{ color: scoreColor(d.riskScore) }}>{d.riskScore}</span>
              </div>
            ))}
          </CardBody>
        </Card>
      )}

      {models.length > 0 && (
        <Card>
          <CardHeader title="Trained Models" subtitle="Each model's own verdict and the levels where it starts to warn"
                      icon={<ICONS.brain size={16} />} />
          <CardBody className="space-y-2">
            {models.map((m) => <ModelRow key={m.name} m={m} />)}
          </CardBody>
        </Card>
      )}

      {prov && (prov.findings.length > 0 || prov.proof) && (
        <Card>
          <CardHeader title="Provenance (What the File Says About Itself)"
                      subtitle={prov.proof ? "The tool that made this file declared it as AI-made" : "Labels found in the file's metadata"}
                      icon={<ICONS.fingerprint size={16} />} />
          <CardBody className="space-y-2">
            {prov.findings.map((f) => (
              <div key={f.label + f.detail} className="rounded-lg border border-default bg-elevated p-3">
                <p className="text-sm font-medium" style={{ color: f.proof ? "var(--color-critical)" : "rgb(203 213 225)" }}>{f.label}</p>
                <p className="text-xs text-slate-400 mt-0.5 break-words">{f.detail}</p>
              </div>
            ))}
          </CardBody>
        </Card>
      )}

      {live && (live.redirectChain.length > 0 || live.page) && (
        <Card>
          <CardHeader title="Read-Only Link Check"
                      subtitle="Where the link really leads (followed without running any page code)"
                      icon={<ICONS.workflow size={16} />} />
          <CardBody className="space-y-3">
            {live.redirectChain.length > 0 && (
              <ol className="space-y-1">
                {live.redirectChain.map((hop, i) => (
                  <li key={hop + i} className="text-xs text-slate-300 mono break-all flex gap-2">
                    <span className="text-slate-500 shrink-0">{i + 1}.</span>{hop}
                  </li>
                ))}
              </ol>
            )}
            {live.status !== "ok" && live.reason && <p className="text-xs text-amber-300">{live.reason}</p>}
            {live.page && (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
                <div className="min-w-0">
                  <Label>Final page title</Label>
                  <p className="text-white truncate" title={live.page.title}>{live.page.title || "—"}</p>
                </div>
                <div>
                  <Label>Asks for a password</Label>
                  <p className="font-semibold" style={{ color: live.page.hasPassword ? "var(--color-warning)" : "var(--color-safe)" }}>
                    {live.page.hasPassword ? "Yes" : "No"}
                  </p>
                </div>
                {live.page.brandsImitated.length > 0 && (
                  <div>
                    <Label>Pretends to be</Label>
                    <p className="text-red-300">{live.page.brandsImitated.join(", ")}</p>
                  </div>
                )}
                {live.page.externalFormTargets.length > 0 && (
                  <div className="min-w-0">
                    <Label>Sends what you type to</Label>
                    <p className="text-red-300 truncate">{live.page.externalFormTargets.join(", ")}</p>
                  </div>
                )}
                {live.page.sensitiveFields.length > 0 && (
                  <div>
                    <Label>Sensitive fields</Label>
                    <p className="text-amber-300">{live.page.sensitiveFields.join(", ")}</p>
                  </div>
                )}
              </div>
            )}
          </CardBody>
        </Card>
      )}
    </>
  );
}
