// Which MITRE ATT&CK techniques have shown up in your own scans, grouped by tactic, each with a
// plain-language explanation, the latest example and a link to the official MITRE page.
import { useEffect, useState } from "react";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { MitreTechniqueRow } from "@/components/mitre/MitreAttack";
import { getMitreSummary, type MitreSummary } from "@/services/api/mitreService";
import { ICONS } from "@/lib/icons";

function ago(iso: string | null) {
  if (!iso) return "";
  const mins = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 60000));
  if (mins < 60) return `${mins}m ago`;
  if (mins < 1440) return `${Math.round(mins / 60)}h ago`;
  return `${Math.round(mins / 1440)}d ago`;
}

export function MitreOverviewCard({ days = 30, limit = 6, compact = false }: { days?: number; limit?: number; compact?: boolean }) {
  const [data, setData] = useState<MitreSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState<string | null>(null);
  const [showAll, setShowAll] = useState(false);

  useEffect(() => {
    getMitreSummary(days).then(setData).catch(() => {}).finally(() => setLoading(false));
  }, [days]);

  const techniques = data?.techniques ?? [];
  const shown = showAll ? techniques : techniques.slice(0, limit);
  const maxTactic = Math.max(1, ...(data?.tactics ?? []).map((t) => t.count));

  return (
    <Card>
      <CardHeader title="MITRE ATT&CK Techniques"
                  subtitle={`Attacker techniques found in your scans, last ${days} days${data ? ` · ${data.mappedScans} risky scan(s) mapped` : ""}`}
                  icon={<ICONS.target size={16} />} />
      <CardBody className="space-y-4">
        {loading && <p className="text-sm text-slate-500 text-center py-4">Loading…</p>}
        {!loading && techniques.length === 0 && (
          <p className="text-sm text-slate-500 text-center py-4">
            No techniques yet. Every risky scan is mapped to MITRE ATT&CK automatically, with an explanation of what the attacker is doing.
          </p>
        )}

        {!compact && (data?.tactics.length ?? 0) > 0 && (
          <div className="space-y-1.5">
            <p className="text-[10px] uppercase tracking-wide text-slate-500">By tactic (the attacker's goal)</p>
            {data!.tactics.map((t) => (
              <div key={t.tactic} className="flex items-center gap-3">
                <span className="w-40 shrink-0 text-xs text-slate-300 truncate" title={t.tactic}>{t.tactic}</span>
                <div className="h-1.5 flex-1 rounded-full bg-elevated overflow-hidden">
                  <div className="h-full rounded-full" style={{ width: `${(t.count / maxTactic) * 100}%`, backgroundColor: "var(--color-brand)" }} />
                </div>
                <span className="w-8 text-right text-xs font-mono text-slate-400">{t.count}</span>
              </div>
            ))}
          </div>
        )}

        <div className="space-y-2">
          {shown.map((t) => (
            <div key={t.id}>
              <button type="button" onClick={() => setOpen(open === t.id ? null : t.id)} aria-expanded={open === t.id}
                      className="w-full flex items-center gap-3 rounded-lg border border-default bg-elevated px-3 py-2 text-left hover:border-cyan-500/50 transition-colors">
                <span className="rounded px-1.5 py-0.5 text-[11px] font-bold mono shrink-0" style={{ color: "var(--color-brand)", backgroundColor: "rgba(34,211,238,0.12)" }}>{t.id}</span>
                <span className="flex-1 min-w-0">
                  <span className="block text-sm text-white truncate">{t.name}</span>
                  <span className="block text-[10px] text-slate-500 truncate">{t.tactic} · last seen {ago(t.lastSeen)}</span>
                </span>
                <span className="text-xs font-mono text-slate-300 shrink-0">{t.count}×</span>
                <ICONS.chevronDown size={14} className={`text-slate-500 shrink-0 transition-transform ${open === t.id ? "rotate-180" : ""}`} />
              </button>
              {open === t.id && (
                <div className="mt-1.5">
                  <MitreTechniqueRow t={t} extra={t.example ? (
                    <p className="text-[11px] text-slate-500 mt-1.5">
                      <span className="font-semibold text-slate-400">Latest example: </span>
                      <span className="mono">{t.example.target}</span> (risk {t.example.riskScore})
                    </p>
                  ) : undefined} />
                </div>
              )}
            </div>
          ))}
        </div>
        {techniques.length > limit && (
          <button type="button" onClick={() => setShowAll((v) => !v)} className="text-xs text-cyan-400 hover:text-cyan-300">
            {showAll ? "Show fewer" : `Show all ${techniques.length} techniques`}
          </button>
        )}
      </CardBody>
    </Card>
  );
}
