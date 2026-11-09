import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/layout/PageHeader";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { AdminOnlyCard } from "@/components/settings/AdminOnlyCard";
import { ApiError } from "@/services/api/client";
import { getPcNetwork, type PcSnapshot } from "@/services/api/pcNetworkService";
import { ICONS } from "@/lib/icons";

const SEV: Record<string, string> = {
  high: "border-red-500/40 bg-red-500/5 text-red-300",
  medium: "border-amber-500/40 bg-amber-500/5 text-amber-300",
  low: "border-slate-500/40 bg-slate-500/5 text-slate-300",
};
const SCOPE: Record<string, string> = {
  "this computer only": "text-emerald-400",
  "your network": "text-amber-400",
  "all networks": "text-orange-400",
};

function Stat({ label, value, hint }: { label: string; value: number | string; hint?: string }) {
  return (
    <div className="rounded-lg border border-default bg-elevated/40 p-3">
      <p className="text-[11px] uppercase tracking-wide text-slate-500">{label}</p>
      <p className="text-2xl font-bold text-white mt-1">{value}</p>
      {hint && <p className="text-[11px] text-slate-500 mt-0.5">{hint}</p>}
    </div>
  );
}

/** (6 Nov) This computer's open ports and live connections - a read-only look, refreshed every 30 seconds. */
export default function PcNetwork() {
  const [snap, setSnap] = useState<PcSnapshot | null>(null);
  const [adminOnly, setAdminOnly] = useState(false);
  const [error, setError] = useState("");
  const [live, setLive] = useState(true);
  const [internetOnly, setInternetOnly] = useState(true);
  const [loading, setLoading] = useState(false);

  const fetchSnap = useCallback(() =>
    getPcNetwork().then((data) => {
      setSnap(data);
      setError("");
    }).catch((e) => {
      if (e instanceof ApiError && e.status === 403) setAdminOnly(true);
      else setError(e instanceof Error ? e.message : "Could not read the network list.");
    }), []);

  async function load() {                     // the "Refresh now" button
    setLoading(true);
    await fetchSnap();
    setLoading(false);
  }

  useEffect(() => {
    fetchSnap();
    if (!live) return;
    const t = window.setInterval(fetchSnap, 30000);
    return () => window.clearInterval(t);
  }, [fetchSnap, live]);

  if (adminOnly) {
    return (
      <div>
        <PageHeader title="PC Network" subtitle="Open ports and live connections of the computer CyberGuard runs on." />
        <AdminOnlyCard title="PC Network" what="Shows the computer's own ports and connections" />
      </div>
    );
  }

  const s = snap?.summary;
  const conns = (snap?.connections ?? []).filter((c) => !internetOnly || c.outside);

  return (
    <div>
      <PageHeader
        title="PC Network"
        subtitle="Which programs on this computer wait for connections (open ports) and who they are talking to right now. Read-only: nothing is closed, blocked or saved."
        action={
          <div className="flex items-center gap-2">
            <label className="flex items-center gap-2 text-xs text-slate-400">
              <input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} /> Refresh every 30 s
            </label>
            <button onClick={load} disabled={loading}
              className="rounded-lg border border-cyan-500/50 text-cyan-300 font-medium px-3 py-1.5 text-xs hover:bg-cyan-500/10 focus-ring disabled:opacity-50">
              {loading ? "Reading…" : "Refresh now"}
            </button>
          </div>
        }
      />

      {error && <p className="text-sm text-red-400 mb-4">{error}</p>}
      {snap && !snap.available && <p className="text-sm text-amber-400 mb-4">{snap.reason}</p>}

      {s && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-4">
          <Stat label="Open ports" value={s.openPorts} hint={`${s.openToNetwork} reachable from the network`} />
          <Stat label="Connections" value={s.connections} hint={`${s.toInternet} to the internet`} />
          <Stat label="Programs online" value={s.programs} />
          <Stat label="High findings" value={s.high} />
          <Stat label="Medium findings" value={s.medium} />
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card className="lg:col-span-2">
          <CardHeader title="What needs a look" subtitle="Plain-language findings. Switch on 'Network connections of this PC' in Settings to have the high ones checked automatically every 30 seconds." icon={<ICONS.warning size={16} />} />
          <CardBody>
            {!snap ? <p className="text-xs text-slate-500">Reading…</p> :
              (snap.findings ?? []).length === 0 ? <p className="text-sm text-emerald-400">Nothing suspicious right now.</p> : (
              <ul className="space-y-2">
                {(snap.findings ?? []).map((f, i) => (
                  <li key={`${f.title}-${i}`} className={`rounded-md border p-3 ${SEV[f.severity] ?? SEV.low}`}>
                    <p className="text-sm font-semibold">{f.title} <span className="text-[11px] uppercase ml-1 opacity-80">{f.severity}</span></p>
                    <p className="text-xs text-slate-300 mt-1">{f.why}</p>
                    {f.fix && f.fix.length > 0 && (
                      <div className="mt-2">
                        <p className="text-[11px] uppercase tracking-wide text-slate-500">What to do</p>
                        <ul className="mt-1 space-y-1 list-disc pl-4 text-xs text-slate-400">
                          {f.fix.map((step, j) => <li key={j}>{step}</li>)}
                        </ul>
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </CardBody>
        </Card>

        <Card>
          <CardHeader title="Open ports" subtitle="Programs waiting for connections, and who can reach them" icon={<ICONS.server size={16} />} />
          <CardBody>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead><tr className="text-left text-slate-500"><th className="py-1 pr-2">Port</th><th className="pr-2">Program</th><th className="pr-2">Reachable from</th><th>Service</th></tr></thead>
                <tbody>
                  {(snap?.listening ?? []).map((l) => (
                    <tr key={`${l.protocol}-${l.address}-${l.port}`} className="border-t border-default">
                      <td className="py-1 pr-2 font-mono text-slate-200">{l.protocol} {l.port}</td>
                      <td className="pr-2 text-slate-300">{l.program}</td>
                      <td className={`pr-2 ${SCOPE[l.scope] ?? "text-slate-400"}`}>{l.scope}</td>
                      <td className="text-slate-400">{l.service || "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardBody>
        </Card>

        <Card>
          <CardHeader title="Live connections" subtitle={`${conns.length} shown${snap?.truncated ? " (first 500)" : ""}`} icon={<ICONS.wifi size={16} />}
            action={<label className="flex items-center gap-1 text-[11px] text-slate-400"><input type="checkbox" checked={internetOnly} onChange={(e) => setInternetOnly(e.target.checked)} /> internet only</label>} />
          <CardBody>
            <div className="overflow-x-auto max-h-96 overflow-y-auto">
              <table className="w-full text-xs">
                <thead><tr className="text-left text-slate-500"><th className="py-1 pr-2">Program</th><th className="pr-2">Remote address</th><th>State</th></tr></thead>
                <tbody>
                  {conns.map((c, i) => (
                    <tr key={`${c.local}-${c.remote}-${c.remotePort}-${i}`} className="border-t border-default">
                      <td className="py-1 pr-2 text-slate-300">{c.program}</td>
                      <td className="pr-2 font-mono text-slate-200">{c.remote}:{c.remotePort}</td>
                      <td className="text-slate-400">{c.status.toLowerCase().replace("_", " ")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardBody>
        </Card>
      </div>
      {snap?.takenAt && <p className="text-[11px] text-slate-600 mt-3">Taken {new Date(snap.takenAt).toLocaleTimeString()} · {snap.note}</p>}
    </div>
  );
}
