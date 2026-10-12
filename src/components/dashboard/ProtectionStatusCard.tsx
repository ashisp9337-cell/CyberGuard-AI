// "What CyberGuard is doing for you": everything that runs in the background, with live numbers —
// automatic protection watchers, IOC memory, MITRE ATT&CK mapping and the trained models behind the scores.
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { getAutomationStatus, type AutomationStatus } from "@/services/api/automationService";
import { getIocSummary, type IocSummary } from "@/services/api/iocService";
import { getMitreSummary, type MitreSummary } from "@/services/api/mitreService";
import { ICONS } from "@/lib/icons";

const STATE_COLOR: Record<string, string> = {
  active: "var(--color-safe)", off: "rgb(100 116 139)", "needs setup": "var(--color-warning)", error: "var(--color-critical)",
};

const MODELS = [
  { name: "Account takeover", data: "RBA dataset · ≈31M real logins" },
  { name: "URL domain model", data: "PhiUSIIL 235,795 URLs + Tranco 1M" },
  { name: "Email & SMS phishing", data: "18,634 emails · 77,891 SMS" },
  { name: "Impersonation", data: "6 subtopic models" },
];

function ago(iso: string | null) {
  if (!iso) return "never";
  const mins = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 60000));
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  if (mins < 1440) return `${Math.round(mins / 60)}h ago`;
  return `${Math.round(mins / 1440)}d ago`;
}

export function ProtectionStatusCard() {
  const [auto, setAuto] = useState<AutomationStatus | null>(null);
  const [iocs, setIocs] = useState<IocSummary | null>(null);
  const [mitre, setMitre] = useState<MitreSummary | null>(null);

  useEffect(() => {
    getAutomationStatus().then(setAuto).catch(() => {});
    getIocSummary().then(setIocs).catch(() => {});
    getMitreSummary(30).then(setMitre).catch(() => {});
  }, []);

  const watchers = auto?.watchers ?? [];
  const activeCount = watchers.filter((w) => w.state === "active").length;
  const checked = watchers.reduce((n, w) => n + (w.checked || 0), 0);

  return (
    <Card>
      <CardHeader title="Protection Status" subtitle="What CyberGuard is doing for you in the background, live"
                  icon={<ICONS.shieldCheck size={16} />}
                  action={<Link to="/settings" className="text-xs text-cyan-400 hover:text-cyan-300">Settings</Link>} />
      <CardBody className="space-y-4">
        <div className="grid grid-cols-3 gap-2 text-center">
          <div className="rounded-lg bg-elevated p-2.5">
            <p className="text-lg font-bold text-white font-mono">{auto ? `${activeCount}/${watchers.length}` : "—"}</p>
            <p className="text-[10px] uppercase tracking-wide text-slate-500">Watchers on</p>
          </div>
          <Link to="/threat-intelligence" className="rounded-lg bg-elevated p-2.5 hover:ring-1 hover:ring-cyan-500/40">
            <p className="text-lg font-bold text-white font-mono">{iocs ? iocs.total : "—"}</p>
            <p className="text-[10px] uppercase tracking-wide text-slate-500">IOCs remembered</p>
          </Link>
          <Link to="/threat-intelligence" className="rounded-lg bg-elevated p-2.5 hover:ring-1 hover:ring-cyan-500/40">
            <p className="text-lg font-bold text-white font-mono">{mitre ? mitre.techniques.length : "—"}</p>
            <p className="text-[10px] uppercase tracking-wide text-slate-500">ATT&CK techniques</p>
          </Link>
        </div>

        <div className="space-y-1.5">
          <p className="text-[10px] uppercase tracking-wide text-slate-500">Automatic protection · {checked} item(s) checked</p>
          {watchers.length === 0 && <p className="text-xs text-slate-500">Status unavailable.</p>}
          {watchers.map((w) => (
            <div key={w.name} className="flex items-center gap-2.5 text-xs">
              <span className="h-2 w-2 rounded-full shrink-0" style={{ backgroundColor: STATE_COLOR[w.state] ?? "rgb(100 116 139)" }} />
              <span className="flex-1 min-w-0 truncate text-slate-200" title={w.what}>{w.title}</span>
              <span className="text-slate-500 shrink-0">{w.state === "active" ? `${w.checked} checked · ${ago(w.lastCheck)}` : w.state}</span>
            </div>
          ))}
        </div>

        <div className="space-y-1.5">
          <p className="text-[10px] uppercase tracking-wide text-slate-500">Trained models behind the scores</p>
          {MODELS.map((m) => (
            <div key={m.name} className="flex items-center justify-between gap-2 text-xs">
              <span className="text-slate-200">{m.name}</span>
              <span className="text-slate-500 text-right">{m.data}</span>
            </div>
          ))}
        </div>

        <ul className="space-y-1 text-[11px] text-slate-400">
          <li className="flex gap-1.5"><ICONS.success size={12} className="text-emerald-400 shrink-0 mt-0.5" />Every risky scan is mapped to MITRE ATT&CK with an explanation</li>
          <li className="flex gap-1.5"><ICONS.success size={12} className="text-emerald-400 shrink-0 mt-0.5" />Repeat threats are flagged “Seen before” from IOC memory</li>
          <li className="flex gap-1.5"><ICONS.success size={12} className="text-emerald-400 shrink-0 mt-0.5" />High and critical threats become incidents and send alerts</li>
          <li className="flex gap-1.5"><ICONS.success size={12} className="text-emerald-400 shrink-0 mt-0.5" />Every sign-in and change is recorded in the Activity Log</li>
        </ul>
      </CardBody>
    </Card>
  );
}
