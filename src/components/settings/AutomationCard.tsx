import { useEffect, useState } from "react";
import { ApiError } from "@/services/api/client";
import { AdminOnlyCard } from "@/components/settings/AdminOnlyCard";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { useToast } from "@/context/ToastContext";
import { ICONS } from "@/lib/icons";
import {
  getAutomationStatus,
  runWatcherNow,
  setWatcherEnabled,
  type AutomationStatus,
  type WatcherStatus,
} from "@/services/api/automationService";

const ICON_FOR: Record<string, keyof typeof ICONS> = {
  email: "email",
  logins: "login",
  windows: "fingerprint",
  downloads: "malware",
};

const STATE_STYLE: Record<string, string> = {
  active: "text-emerald-400",
  off: "text-slate-500",
  "needs setup": "text-amber-400",
  error: "text-red-400",
};

const VERDICT_STYLE: Record<string, string> = {
  safe: "text-emerald-400",
  low_risk: "text-sky-400",
  suspicious: "text-amber-400",
  high_risk: "text-orange-400",
  critical: "text-red-400",
};

function timeAgo(iso: string | null): string {
  if (!iso) return "not yet";
  const secs = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.round(secs / 60)} min ago`;
  return `${Math.round(secs / 3600)} h ago`;
}

function WatcherRow({ w, onChange }: { w: WatcherStatus; onChange: (w: WatcherStatus) => void }) {
  const { notify } = useToast();
  const [busy, setBusy] = useState(false);
  const Icon = ICONS[ICON_FOR[w.name] ?? "shieldCheck"];

  async function toggle() {
    setBusy(true);
    try {
      onChange(await setWatcherEnabled(w.name, !w.enabled));
    } catch (err) {
      notify({ variant: "critical", title: "Could not change it", description: err instanceof Error ? err.message : "" });
    } finally {
      setBusy(false);
    }
  }

  async function runNow() {
    setBusy(true);
    try {
      const res = await runWatcherNow(w.name);
      onChange(res);
      notify(
        res.lastError
          ? { variant: "critical", title: `${w.title}: problem`, description: res.lastError }
          : { variant: "success", title: `${w.title} checked`, description: res.note || res.setupHint || "Done" },
      );
    } catch (err) {
      notify({ variant: "critical", title: "Check failed", description: err instanceof Error ? err.message : "" });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="rounded-lg border border-default bg-elevated/40 p-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="flex items-center gap-2 text-sm font-medium text-white">
            <Icon size={15} /> {w.title}
            <span className={`text-xs font-medium capitalize ${STATE_STYLE[w.state] ?? "text-slate-400"}`}>• {w.state}</span>
          </p>
          <p className="text-xs text-slate-400 mt-1">{w.what}</p>
        </div>
        <button
          role="switch"
          aria-checked={w.enabled}
          aria-label={`Automatic ${w.title}`}
          onClick={toggle}
          disabled={busy}
          className={`relative h-6 w-11 rounded-full transition-colors focus-ring shrink-0 disabled:opacity-50 ${w.enabled ? "bg-cyan-500" : "bg-elevated border border-strong"}`}
        >
          <span className={`absolute top-0.5 h-5 w-5 rounded-full bg-white transition-transform ${w.enabled ? "translate-x-5" : "translate-x-0.5"}`} />
        </button>
      </div>

      {w.state === "needs setup" && <p className="text-xs text-amber-400 mt-2">Setup: {w.setupHint}</p>}
      {w.lastError && <p className="text-xs text-red-400 mt-2 break-words">Problem: {w.lastError}</p>}
      {w.lastFinding && <p className="text-xs text-red-300 mt-2 break-words">Last threat: {w.lastFinding}</p>}

      {w.recent?.length > 0 && (
        <div className="mt-2 rounded-md border border-default bg-elevated/70 p-2">
          <p className="text-[11px] uppercase tracking-wide text-slate-500 mb-1">Recently checked</p>
          <ul className="space-y-1">
            {w.recent.slice(0, 5).map((r, i) => (
              <li key={`${r.at}-${i}`} className="flex items-center justify-between gap-2 text-xs">
                <span className="text-slate-300 truncate" title={r.item}>{r.item}</span>
                <span className={`shrink-0 font-medium ${VERDICT_STYLE[r.classification] ?? "text-slate-400"}`}>
                  {r.classification.replace("_", " ")} · {r.score}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="mt-2 flex items-center justify-between gap-3 flex-wrap">
        <p className="text-xs text-slate-500">
          Checked {w.checked} · threats {w.threats} · last check {timeAgo(w.lastCheck)} · every{" "}
          {w.intervalSeconds >= 60 ? `${Math.round(w.intervalSeconds / 60)} min` : `${w.intervalSeconds}s`}
          {w.note ? ` · ${w.note}` : ""}
        </p>
        <button
          onClick={runNow}
          disabled={busy || !w.enabled}
          className="rounded-lg border border-cyan-500/50 text-cyan-300 font-medium px-3 py-1.5 text-xs hover:bg-cyan-500/10 focus-ring disabled:opacity-50"
        >
          {busy ? "Checking…" : "Check now"}
        </button>
      </div>
      <p className="text-[11px] text-slate-600 mt-1">
        Modules: {w.modules.join(", ")} · {w.technology}
      </p>
    </div>
  );
}

export function AutomationCard() {
  const [status, setStatus] = useState<AutomationStatus | null>(null);
  const [adminOnly, setAdminOnly] = useState(false);

  useEffect(() => {
    let alive = true;
    let timer = 0;
    const load = () => getAutomationStatus().then((s) => alive && setStatus(s)).catch((e) => {
      if (e instanceof ApiError && e.status === 403) {        // only the administrator manages this
        setAdminOnly(true);
        window.clearInterval(timer);
      }
    });
    load();
    timer = window.setInterval(load, 10000);          // live status every 10 s
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, []);

  function replace(w: WatcherStatus) {
    setStatus((s) => (s ? { ...s, watchers: s.watchers.map((x) => (x.name === w.name ? w : x)) } : s));
  }

  if (adminOnly) {
    return <AdminOnlyCard title="Automatic Protection" what="Background checks of the Gmail inbox, Downloads folder and sign-ins" />;
  }

  return (
    <Card className="lg:col-span-2">
      <CardHeader
        title="Automatic Protection"
        subtitle="CYBERGUARD checks these by itself in the background — no manual scanning needed. Findings appear in Scan History, Live Monitoring and your alert channels."
        icon={<ICONS.radar size={16} />}
      />
      <CardBody>
        {status && !status.enabled && (
          <p className="text-xs text-amber-400 mb-3">
            Automation is switched off for the whole backend (AUTOMATION_ENABLED=false in backend/.env).
          </p>
        )}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {status === null ? (
            <p className="text-xs text-slate-500">Loading…</p>
          ) : (
            status.watchers.map((w) => <WatcherRow key={w.name} w={w} onChange={replace} />)
          )}
        </div>
        <p className="text-xs text-slate-500 mt-3">
          Nothing is ever deleted or opened. Emails are read without being marked as read; a dangerous inbox email is moved
          to the Gmail label “CyberGuard-Quarantine” and a dangerous download to CyberGuard’s quarantine folder — both
          can be undone (Release / Restore). Windows logs are only read.
        </p>
      </CardBody>
    </Card>
  );
}
