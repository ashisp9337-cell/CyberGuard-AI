import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/layout/PageHeader";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { devicesService, type DeviceDetail, type DeviceRow, type DevicesResponse, type NewDevice } from "@/services/api/devicesService";
import { companyService, type Employee } from "@/services/api/companyService";
import { API_CONFIG } from "@/services/api/config";
import { useToast } from "@/context/ToastContext";
import { formatRelativeTime } from "@/lib/utils";
import { ICONS } from "@/lib/icons";
import { cn } from "@/lib/utils";

const COLLECTORS: { key: string; label: string; what: string }[] = [
  { key: "network", label: "Network", what: "open ports + live connections" },
  { key: "logons", label: "Windows sign-ins", what: "failed / successful logons (needs administrator)" },
  { key: "dns", label: "Websites", what: "website names looked up (only dangerous ones are kept)" },
  { key: "downloads", label: "Downloads", what: "new risky files checked for malware" },
];
const RISK = (r: number) => (r >= 86 ? "text-red-400" : r >= 71 ? "text-orange-400" : r >= 51 ? "text-amber-400" : "text-emerald-400");
const seen = (iso: string | null | undefined) => (iso ? formatRelativeTime(iso) : "never");

function Stat({ label, value, hint, tone }: { label: string; value: number | string; hint?: string; tone?: string }) {
  return (
    <div className="rounded-lg border border-default bg-elevated/40 p-3">
      <p className="text-[11px] uppercase tracking-wide text-slate-500">{label}</p>
      <p className={cn("text-2xl font-bold mt-1", tone ?? "text-white")}>{value}</p>
      {hint && <p className="text-[11px] text-slate-500 mt-0.5">{hint}</p>}
    </div>
  );
}

function serverAddress(): string {
  return (API_CONFIG.baseUrl || window.location.origin).replace(/\/$/, "");
}

/** (10 Nov) Company mode: PCs that run the CyberGuard Agent. Administrators see every PC, employees their own. */
export default function Devices() {
  const { notify } = useToast();
  const [data, setData] = useState<DevicesResponse | null>(null);
  const [error, setError] = useState("");
  const [people, setPeople] = useState<Employee[]>([]);
  const [name, setName] = useState("");
  const [owner, setOwner] = useState("");
  const [busy, setBusy] = useState("");
  const [created, setCreated] = useState<NewDevice | null>(null);
  const [copied, setCopied] = useState(false);
  const [detail, setDetail] = useState<DeviceDetail | null>(null);
  const [confirm, setConfirm] = useState("");

  const load = useCallback(() =>
    devicesService.list().then((d) => {
      setData(d);
      setError("");
    }).catch((e) => setError(e instanceof Error ? e.message : "Could not load the devices.")), []);

  useEffect(() => {
    load();
    const t = window.setInterval(load, 30000);
    return () => window.clearInterval(t);
  }, [load]);

  useEffect(() => {                                          // administrators can add a PC for any employee
    if (data?.admin) companyService.employees().then((r) => setPeople(r.employees.filter((p) => p.active))).catch(() => setPeople([]));
  }, [data?.admin]);

  useEffect(() => {
    if (!confirm) return;
    const t = window.setTimeout(() => setConfirm(""), 4000);
    return () => window.clearTimeout(t);
  }, [confirm]);

  useEffect(() => {
    if (detail) document.getElementById("device-detail")?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [detail?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setBusy("create");
    try {
      const d = await devicesService.create(name.trim() || "My PC", owner || undefined);
      setCreated(d);
      setCopied(false);
      setName("");
      await load();
    } catch (err) {
      notify({ variant: "critical", title: "Could not add the PC", description: err instanceof Error ? err.message : "Please try again." });
    } finally {
      setBusy("");
    }
  }

  async function copyKey() {
    if (!created) return;
    try {
      await navigator.clipboard.writeText(created.key);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  async function open(d: DeviceRow) {
    if (detail?.id === d.id) {
      setDetail(null);
      return;
    }
    try {
      setDetail(await devicesService.get(d.id));
    } catch (e) {
      notify({ variant: "critical", title: "Could not load", description: e instanceof Error ? e.message : "" });
    }
  }

  async function remove(d: DeviceRow) {
    if (confirm !== d.id) {
      setConfirm(d.id);
      return;
    }
    setConfirm("");
    setBusy(`rm:${d.id}`);
    try {
      await devicesService.remove(d.id);
      notify({ variant: "success", title: `${d.name} removed`, description: "Its key stops working at once." });
      if (detail?.id === d.id) setDetail(null);
      await load();
    } catch (e) {
      notify({ variant: "critical", title: "Not removed", description: e instanceof Error ? e.message : "" });
    } finally {
      setBusy("");
    }
  }

  const s = data?.summary;
  const admin = data?.admin;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Devices"
        subtitle={admin
          ? "Every company PC that runs the CyberGuard Agent: its live status and what CyberGuard found on it. Employees see their own PCs here; you see all of them."
          : "Your PCs that run the CyberGuard Agent: their live status and what CyberGuard found on them. Your administrator can see them too."}
        action={<Button variant="outline" size="sm" onClick={() => load()}><ICONS.refresh size={14} /> Refresh</Button>}
      />
      {error && <p className="text-sm text-red-400" role="alert">{error}</p>}

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <Stat label="PCs" value={s?.total ?? "–"} />
        <Stat label="Online now" value={s?.online ?? "–"} tone="text-emerald-400" hint="reported in the last 3 min" />
        <Stat label="PCs with findings" value={s?.withFindings24h ?? "–"} tone={s?.withFindings24h ? "text-orange-400" : undefined} hint="last 24 hours" />
        <Stat label="Findings" value={s?.findings24h ?? "–"} tone={s?.findings24h ? "text-orange-400" : undefined} hint="last 24 hours" />
      </div>

      <Card>
        <CardHeader title="Add a PC" icon={<ICONS.device size={16} />}
          subtitle="Makes a device key for the CyberGuard Agent. The agent only reads security facts and never blocks or deletes anything." />
        <CardBody>
          <form onSubmit={create} className="flex flex-col sm:flex-row gap-2">
            <input value={name} onChange={(e) => setName(e.target.value)} maxLength={60} placeholder="Name of the PC, e.g. Reception laptop"
              aria-label="Name of the PC"
              className="flex-1 rounded-lg border border-strong bg-elevated px-3 py-2 text-sm text-white placeholder:text-slate-500 focus-ring" />
            {admin && people.length > 0 && (
              <select value={owner} onChange={(e) => setOwner(e.target.value)} aria-label="Whose PC"
                className="rounded-lg border border-strong bg-elevated px-3 py-2 text-sm text-white focus-ring">
                <option value="">My own PC</option>
                {people.map((p) => <option key={p.id} value={p.id}>{p.name} ({p.email})</option>)}
              </select>
            )}
            <Button type="submit" disabled={busy === "create"}>{busy === "create" ? "Creating…" : "Create device key"}</Button>
          </form>

          {created && (
            <div className="mt-4 rounded-lg border border-cyan-500/30 bg-cyan-500/5 p-4 text-sm space-y-3">
              <p className="text-white font-medium">Key for {created.name} — shown only once:</p>
              <div className="flex flex-col sm:flex-row gap-2">
                <code className="flex-1 rounded bg-black/40 px-3 py-2 text-xs text-cyan-200 break-all select-all">{created.key}</code>
                <Button variant="outline" size="sm" onClick={copyKey}>{copied ? "Copied" : "Copy key"}</Button>
              </div>
              <ol className="list-decimal ml-5 space-y-1.5 text-slate-300 text-xs">
                <li>On that PC: install Python 3 (python.org) and copy the project's <code className="text-cyan-300">agent</code> folder to it.</li>
                <li>In that folder run <code className="text-cyan-300">python -m pip install psutil</code>, then <code className="text-cyan-300">python cyberguard_agent.py --setup</code>.</li>
                <li>Server address: <code className="text-cyan-300 break-all">{serverAddress()}</code> — then paste the key above.</li>
                <li>Start it with <code className="text-cyan-300">python cyberguard_agent.py</code>. For Windows sign-in checks open the terminal with "Run as administrator". The PC appears below as online within a minute.</li>
              </ol>
              <Button variant="ghost" size="sm" onClick={() => setCreated(null)}>I have copied it — hide the key</Button>
            </div>
          )}
        </CardBody>
      </Card>

      <div className="space-y-3">
        {data && data.devices.length === 0 && (
          <Card><CardBody><p className="text-sm text-slate-400">No PCs yet. Create a device key above and start the agent on the PC.</p></CardBody></Card>
        )}
        {(data?.devices ?? []).map((d) => (
          <Card key={d.id}>
            <CardBody>
              <div className="flex flex-col lg:flex-row lg:items-start gap-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={cn("h-2.5 w-2.5 rounded-full shrink-0", d.online ? "bg-emerald-400" : d.paired ? "bg-slate-600" : "bg-amber-400")} />
                    <span className="font-semibold text-white">{d.name}</span>
                    {d.hostname && d.hostname !== d.name && <span className="text-xs text-slate-500">{d.hostname}</span>}
                    <span className={cn("text-xs", d.online ? "text-emerald-400" : d.paired ? "text-slate-500" : "text-amber-400")}>
                      {d.online ? "online" : d.paired ? `offline · last report ${seen(d.lastSeen)}` : "waiting for the agent to start"}
                    </span>
                  </div>
                  <p className="text-xs text-slate-500 mt-1">
                    {admin && <>{d.owner.name} ({d.owner.email}) · </>}
                    {[d.os, d.agentVersion && `agent ${d.agentVersion}`, d.lastIp].filter(Boolean).join(" · ") || "not connected yet"}
                  </p>
                  <div className="flex flex-wrap gap-1.5 mt-2.5">
                    {COLLECTORS.map((c) => {
                      const st = d.collectors[c.key];
                      const has = d.collectorsAvailable.includes(c.key);
                      return (
                        <span key={c.key} title={st?.note ?? c.what}
                          className={cn("text-[11px] rounded border px-2 py-0.5",
                            st ? "border-emerald-500/30 text-emerald-300" : has ? "border-slate-600 text-slate-400" : "border-slate-700 text-slate-600")}>
                          {c.label}{st ? ` · ${seen(st.at)}` : has ? " · nothing yet" : " · not on this PC"}
                        </span>
                      );
                    })}
                  </div>
                </div>
                <div className="lg:text-right shrink-0">
                  <p className="text-xs text-slate-500">Findings (24 h / total)</p>
                  <p className="text-lg font-bold">
                    <span className={d.findings24h ? RISK(d.highestRisk24h) : "text-white"}>{d.findings24h}</span>
                    <span className="text-slate-500 text-sm"> / {d.findingsTotal}</span>
                  </p>
                  {d.lastFinding && <p className="text-xs text-slate-500 max-w-[260px] truncate">last: {d.lastFinding.title}</p>}
                  <div className="flex lg:justify-end gap-1.5 mt-2">
                    <Button variant="outline" size="sm" onClick={() => open(d)}>{detail?.id === d.id ? "Hide" : "Details"}</Button>
                    <Button variant="ghost" size="sm" className="text-red-300 hover:text-red-200" disabled={busy === `rm:${d.id}`} onClick={() => remove(d)}>
                      {confirm === d.id ? "Click again to remove" : "Remove"}
                    </Button>
                  </div>
                </div>
              </div>
            </CardBody>
          </Card>
        ))}
      </div>

      {detail && (
        <Card id="device-detail">
          <CardHeader title={`${detail.name} — details`} icon={<ICONS.device size={16} />}
            subtitle={`${detail.hostname || "–"} · ${detail.os || "–"} · last report ${seen(detail.lastSeen)}`}
            action={<Button variant="ghost" size="sm" onClick={() => setDetail(null)}>Close</Button>} />
          <CardBody className="grid lg:grid-cols-2 gap-6">
            <div>
              <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 mb-2">Findings on this PC</p>
              {detail.findings.length === 0 ? <p className="text-sm text-slate-500">Nothing found so far.</p> : (
                <ul className="space-y-3">
                  {detail.findings.map((f) => (
                    <li key={f.id} className="text-xs">
                      <p><span className={cn("font-semibold", RISK(f.risk))}>{f.risk}</span>
                        <span className="text-slate-200"> · {f.title}</span>
                        <span className="text-slate-500"> · {f.collector} · {seen(f.at)}</span></p>
                      <p className="text-slate-500 mt-0.5 line-clamp-2">{f.explanation}</p>
                    </li>
                  ))}
                </ul>
              )}
            </div>
            <div className="space-y-5">
              <div>
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 mb-2">Network (latest report)</p>
                {!detail.networkLast ? <p className="text-sm text-slate-500">No network report yet.</p> : (
                  <div className="text-xs space-y-2">
                    <p className="text-slate-400">{detail.networkLast.summary.openPorts} open port(s), {detail.networkLast.summary.openToNetwork} reachable from the network, {detail.networkLast.summary.connections} connection(s) · {seen(detail.networkLast.takenAt)}</p>
                    {detail.networkLast.listening.length > 0 && (
                      <ul className="space-y-1">
                        {detail.networkLast.listening.slice(0, 12).map((l, i) => (
                          <li key={i} className="text-slate-300">{l.protocol} {l.port}{l.service ? ` (${l.service})` : ""} · {l.program} · <span className="text-amber-300">{l.scope}</span></li>
                        ))}
                      </ul>
                    )}
                    {detail.networkLast.topRemote.length > 0 && (
                      <p className="text-slate-500">Talks most to: {detail.networkLast.topRemote.slice(0, 5).map((r) => `${r.address} (${r.connections})`).join(", ")}</p>
                    )}
                  </div>
                )}
              </div>
              <div>
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 mb-2">Risky downloads checked</p>
                {detail.recentDownloads.length === 0 ? <p className="text-sm text-slate-500">None yet.</p> : (
                  <ul className="space-y-1 text-xs">
                    {detail.recentDownloads.slice().reverse().map((r, i) => (
                      <li key={i}><span className={cn("font-semibold", RISK(r.score))}>{r.score}</span> <span className="text-slate-300">{r.name}</span> <span className="text-slate-500">· {seen(r.at)}</span></li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          </CardBody>
        </Card>
      )}
    </div>
  );
}
