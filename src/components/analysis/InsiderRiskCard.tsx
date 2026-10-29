// Insider Risk (mini-SOC / UEBA): one engine, three lenses - data exfiltration, abnormal activity, insider pattern.
// Shows the triage queue the backend built from an uploaded activity log (backend app/detectors/insider_risk.py).
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { ICONS } from "@/lib/icons";
import type { InsiderRiskInfo, InsiderQueueEntry } from "@/types";

const LEVEL_META: Record<string, { label: string; color: string; bg: string }> = {
  alert: { label: "Alert", color: "var(--color-critical)", bg: "var(--color-critical-bg)" },
  review: { label: "Review", color: "var(--color-high)", bg: "var(--color-high-bg)" },
};

function LevelChip({ level }: { level: string }) {
  const m = LEVEL_META[level] ?? { label: level || "-", color: "var(--color-info)", bg: "var(--color-info-bg)" };
  return (
    <span className="shrink-0 rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide"
          style={{ color: m.color, backgroundColor: m.bg }}>
      {m.label}
    </span>
  );
}

// Last 30 days of one person: each bar is a day, its height is the risk percentile (only the top 10% is drawn tall).
function RiskStrip({ q, review }: { q: InsiderQueueEntry; review: number }) {
  if (!q.timeline.length) return null;
  return (
    <div className="flex items-end gap-px h-6 mt-2" aria-label={`Risk of ${q.user}, day by day`}>
      {q.timeline.map((t) => {
        const r = t.risk ?? 0;
        const h = Math.max(2, Math.min(24, ((Math.max(r, 90) - 90) / 10) * 24));
        const color = t.level === "alert" ? "var(--color-critical)" : t.level === "review" ? "var(--color-high)"
          : r >= review - 4 ? "var(--color-medium, #eab308)" : "var(--color-info)";
        return <div key={t.date} title={r >= 99.995 ? `${t.date}: beyond every ordinary day seen in training` : `${t.date}: riskier than ${r.toFixed(1)}% of ordinary days`}
                    className="w-1.5 rounded-sm" style={{ height: `${h}px`, backgroundColor: color, opacity: 0.85 }} />;
      })}
    </div>
  );
}

function Lens({ title, items, icon }: { title: string; items: string[]; icon: React.ReactNode }) {
  if (!items.length) return null;
  return (
    <div className="min-w-0">
      <p className="text-[10px] uppercase tracking-wide text-slate-500 flex items-center gap-1">{icon}{title}</p>
      <ul className="mt-1 space-y-0.5">
        {items.map((s) => <li key={s} className="text-xs text-slate-300">• {s}</li>)}
      </ul>
    </div>
  );
}

export function InsiderRiskCard({ ir }: { ir: InsiderRiskInfo }) {
  const review = ir.reviewLevel ?? 99;
  const lenses = [
    { key: "exfiltration", title: "Data exfiltration", n: ir.lenses.exfiltration, icon: <ICONS.exfiltration size={14} /> },
    { key: "abnormal", title: "Abnormal activity", n: ir.lenses.abnormal, icon: <ICONS.behavior size={14} /> },
    { key: "insider", title: "Insider pattern", n: ir.lenses.insider, icon: <ICONS.insider size={14} /> },
  ];
  return (
    <Card>
      <CardHeader title="Insider Risk - Triage Queue"
                  subtitle={`${ir.people} people · ${ir.userDays.toLocaleString()} person-days · ${ir.events.toLocaleString()} events (${ir.format})`}
                  icon={<ICONS.insider size={16} />} />
      <CardBody className="space-y-4">
        <div className="grid grid-cols-3 gap-2">
          {lenses.map((l) => (
            <div key={l.key} className="rounded-lg border border-default bg-elevated p-3">
              <p className="text-[10px] uppercase tracking-wide text-slate-500 flex items-center gap-1">{l.icon}{l.title}</p>
              <p className="text-xl font-bold text-white mt-1">{l.n}</p>
              <p className="text-[10px] text-slate-500">{l.n === 1 ? "person" : "people"} flagged</p>
            </div>
          ))}
        </div>

        {ir.queue.length === 0 ? (
          <p className="text-sm text-slate-500 py-2 text-center">Nobody reached the review level.</p>
        ) : (
          <ol className="space-y-2">
            {ir.queue.map((q, i) => (
              <li key={q.user} className="rounded-lg border border-default bg-elevated p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-xs text-slate-500 w-5">{i + 1}.</span>
                  <span className="text-sm font-semibold text-white mono">{q.user}</span>
                  <LevelChip level={q.level} />
                  {q.pattern && <span className="text-xs text-slate-300">{q.pattern.name}</span>}
                  <span className="ml-auto text-[11px] text-slate-500">
                    {ir.trained && q.risk != null
                      ? (q.risk >= 99.995 ? "beyond every ordinary day seen in training · " : `riskier than ${q.risk.toFixed(2)}% of ordinary days · `)
                      : ""}
                    {q.date} · {q.flaggedDays} day(s) flagged
                  </span>
                </div>
                {i < 5 && (
                  <div className="grid sm:grid-cols-2 gap-3 mt-2">
                    <Lens title="Data exfiltration" items={q.exfiltration} icon={<ICONS.exfiltration size={12} />} />
                    <Lens title="Abnormal activity" items={q.abnormal} icon={<ICONS.behavior size={12} />} />
                  </div>
                )}
                {i < 5 && q.pattern && (
                  <p className="text-xs text-slate-400 mt-2"><span className="text-slate-500">Why this pattern: </span>{q.pattern.why}</p>
                )}
                <RiskStrip q={q} review={review} />
              </li>
            ))}
          </ol>
        )}

        {ir.notes.length > 0 && (
          <ul className="space-y-0.5">
            {ir.notes.map((n) => <li key={n} className="text-xs text-slate-400">• {n}</li>)}
          </ul>
        )}
        <p className="text-[11px] text-slate-500 leading-relaxed">
          {ir.trained
            ? `Tested on CERT r4.2 (a simulated company): ${ir.testCaught} of ${ir.testOf} insiders it never saw were in the top 10 of their day; about ${ir.falseAlertsPerDay ?? "?"} ordinary person-days per day also reached alert level. This is a review queue for an analyst - check with HR before acting on anyone.`
            : "The insider-risk model is not trained yet, so only rule findings are shown."}
        </p>
      </CardBody>
    </Card>
  );
}
