// MITRE ATT&CK display pieces. Every technique ID is always shown together with its name, tactic and a
// plain-language explanation of what the attacker is doing, plus a link to the official MITRE page.
import { useState, type ReactNode } from "react";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { ICONS } from "@/lib/icons";
import type { MitreTechnique } from "@/types";

export function MitreIdChip({ t, active, onClick }: { t: Pick<MitreTechnique, "id" | "name" | "explanation">; active?: boolean; onClick?: () => void }) {
  const cls = "inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-semibold mono border transition-colors";
  const style = active
    ? { borderColor: "var(--color-brand)", color: "var(--color-brand)", backgroundColor: "rgba(34,211,238,0.12)" }
    : { borderColor: "var(--color-border)", color: "rgb(148 163 184)" };
  return onClick ? (
    <button type="button" onClick={(e) => { e.stopPropagation(); onClick(); }} className={cls} style={style}
            title={`${t.id} · ${t.name}: ${t.explanation}`} aria-expanded={active}>
      {t.id}
    </button>
  ) : (
    <span className={cls} style={style} title={`${t.id} · ${t.name}: ${t.explanation}`}>{t.id}</span>
  );
}

/** One technique, fully explained. */
export function MitreTechniqueRow({ t, extra }: { t: MitreTechnique; extra?: ReactNode }) {
  return (
    <div className="rounded-lg border border-default bg-elevated p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="rounded px-1.5 py-0.5 text-[11px] font-bold mono" style={{ color: "var(--color-brand)", backgroundColor: "rgba(34,211,238,0.12)" }}>
          {t.id}
        </span>
        <p className="text-sm font-semibold text-white">{t.name}</p>
        {t.tactic && (
          <span className="rounded-full border border-default px-2 py-0.5 text-[10px] uppercase tracking-wide text-slate-400">{t.tactic}</span>
        )}
      </div>
      <p className="text-xs text-slate-300 mt-1.5 leading-relaxed">{t.explanation}</p>
      {t.evidence && t.evidence.length > 0 && (
        <p className="text-[11px] text-slate-500 mt-1.5">
          <span className="font-semibold text-slate-400">Why it was mapped: </span>{t.evidence.join(" · ")}
        </p>
      )}
      {extra}
      <a href={t.url} target="_blank" rel="noopener noreferrer"
         className="mt-2 inline-flex items-center gap-1 text-[11px] font-medium text-cyan-400 hover:text-cyan-300">
        Read {t.id} on MITRE ATT&CK <ICONS.externalLink size={11} />
      </a>
    </div>
  );
}

/** Card on a scan result: the attacker techniques this threat points to. */
export function MitreAttackCard({ techniques }: { techniques: MitreTechnique[] }) {
  if (!techniques.length) return null;
  return (
    <Card>
      <CardHeader title="MITRE ATT&CK Mapping" subtitle="The attacker techniques this threat matches, in plain language"
                  icon={<ICONS.target size={16} />} />
      <CardBody className="space-y-2">
        {techniques.map((t) => <MitreTechniqueRow key={t.id} t={t} />)}
        <p className="text-[11px] text-slate-500 pt-1">
          MITRE ATT&CK is the public catalogue of real attacker behaviour used by security teams worldwide.
        </p>
      </CardBody>
    </Card>
  );
}

/** Compact chips for lists (incidents, history). Clicking a chip opens its explanation underneath. */
export function MitreChips({ techniques }: { techniques: MitreTechnique[] }) {
  const [open, setOpen] = useState<string | null>(null);
  if (!techniques.length) return null;
  const sel = techniques.find((t) => t.id === open);
  return (
    <div className="mt-1">
      <div className="flex flex-wrap items-center gap-1">
        <span className="text-[10px] text-slate-500 mr-0.5">ATT&CK</span>
        {techniques.map((t) => (
          <MitreIdChip key={t.id} t={t} active={open === t.id} onClick={() => setOpen(open === t.id ? null : t.id)} />
        ))}
      </div>
      {sel && (
        <div className="mt-1.5 rounded-md border border-default bg-canvas p-2" onClick={(e) => e.stopPropagation()}>
          <p className="text-xs font-semibold text-white">
            {sel.id} · {sel.name} <span className="font-normal text-slate-500">({sel.tactic})</span>
          </p>
          <p className="text-[11px] text-slate-400 mt-0.5 leading-relaxed">{sel.explanation}</p>
          <a href={sel.url} target="_blank" rel="noopener noreferrer" className="mt-1 inline-flex items-center gap-1 text-[11px] text-cyan-400 hover:text-cyan-300">
            MITRE ATT&CK page <ICONS.externalLink size={10} />
          </a>
        </div>
      )}
    </div>
  );
}
