import { useCallback, useEffect, useMemo, useState } from "react";
import { PageHeader } from "@/components/layout/PageHeader";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { AdminOnlyCard } from "@/components/settings/AdminOnlyCard";
import { ApiError } from "@/services/api/client";
import {
  getPcNetwork, blockPort, blockAddress, unblock, closeConnection, endProcess,
  type PcSnapshot, type PcConnection, type PcActionResult,
} from "@/services/api/pcNetworkService";
import { useToast } from "@/context/ToastContext";
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
const RISK: Record<string, string> = {
  high: "bg-red-500/15 text-red-300 border-red-500/40",
  medium: "bg-amber-500/15 text-amber-300 border-amber-500/40",
  low: "bg-emerald-500/10 text-emerald-300 border-emerald-500/30",
  none: "bg-slate-500/10 text-slate-400 border-slate-500/30",
};
const BTN = "rounded border px-1.5 py-0.5 text-[11px] font-medium focus-ring disabled:opacity-40 disabled:cursor-not-allowed";
const BTN_RED = `${BTN} border-red-500/50 text-red-300 hover:bg-red-500/10`;
const BTN_AMBER = `${BTN} border-amber-500/50 text-amber-300 hover:bg-amber-500/10`;
const BTN_CYAN = `${BTN} border-cyan-500/50 text-cyan-300 hover:bg-cyan-500/10`;

function Stat({ label, value, hint }: { label: string; value: number | string; hint?: string }) {
  return (
    <div className="rounded-lg border border-default bg-elevated/40 p-3">
      <p className="text-[11px] uppercase tracking-wide text-slate-500">{label}</p>
      <p className="text-2xl font-bold text-white mt-1">{value}</p>
      {hint && <p className="text-[11px] text-slate-500 mt-0.5">{hint}</p>}
    </div>
  );
}

/** (6 Nov) This computer's open ports and live connections, refreshed every 30 seconds.
 *  (10 Nov) + open / closed port list, who is on the other side of each connection, and actions: block a port or an
 *  address (Windows Firewall, can be undone), close one connection, end a program - each asks for confirmation. */
export default function PcNetwork() {
  const { notify } = useToast();
  const [snap, setSnap] = useState<PcSnapshot | null>(null);
  const [adminOnly, setAdminOnly] = useState(false);
  const [error, setError] = useState("");
  const [live, setLive] = useState(true);
  const [internetOnly, setInternetOnly] = useState(true);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState("");
  const [filter, setFilter] = useState("");
  const [showClosed, setShowClosed] = useState(true);

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

  /** Every action: ask first, run it, show the result, then read the network again. */
  async function act(key: string, question: string, run: () => Promise<PcActionResult>) {
    if (!window.confirm(question)) return;
    setBusy(key);
    try {
      const r = await run();
      notify({ variant: "success", title: "Done", description: r.message });
    } catch (e) {
      notify({ variant: "warning", title: "Not done", description: e instanceof Error ? e.message : "The action failed." });
    } finally {
      setBusy("");
      await fetchSnap();
    }
  }

  const a = snap?.actions;
  const canFirewall = !!(a?.enabled && a.firewall);
  const canClose = !!(a?.enabled && a.closeConnection);
  const canEnd = !!(a?.enabled && a.endProcess);
  const blockedPorts = useMemo(() => new Set((snap?.blocked ?? []).filter((b) => b.kind === "port").map((b) => b.port)),
    [snap?.blocked]);
  const blockedAddrs = useMemo(() => new Set((snap?.blocked ?? []).filter((b) => b.kind === "address").map((b) => b.address)),
    [snap?.blocked]);

  if (adminOnly) {
    return (
      <div>
        <PageHeader title="PC Network" subtitle="Open ports and live connections of the computer CyberGuard runs on." />
        <AdminOnlyCard title="PC Network" what="Shows the computer's own ports and connections" />
      </div>
    );
  }

  const s = snap?.summary;
  const q = filter.trim().toLowerCase();
  const conns = (snap?.connections ?? []).filter((c) => (!internetOnly || c.outside) && (!q ||
    `${c.program} ${c.remote} ${c.remotePort} ${c.remoteName ?? ""} ${c.owner ?? ""} ${c.status}`.toLowerCase().includes(q)));
  const ports = (snap?.portStatus ?? []).filter((p) => showClosed || p.state === "open");
  const meaning = snap?.stateMeaning ?? {};

  const endBtn = (pid: number | null | undefined, program: string, key: string, allowed?: boolean) =>
    pid && pid > 4 && allowed ? (
      <button className={BTN_RED} disabled={!canEnd || busy !== ""} title={canEnd ? "End this program" : a?.reason}
        onClick={() => act(key, `End ${program} (process ${pid})?\n\nUnsaved work in it is lost. Windows' own programs, `
          + "the database and CyberGuard are refused.", () => endProcess(pid, program))}>
        End program
      </button>
    ) : null;

  const closeBtn = (c: PcConnection, key: string) => (
    <button className={BTN_AMBER} disabled={!canClose || busy !== "" || c.protocol !== "TCP" || c.remote.includes(":")}
      title={c.remote.includes(":") ? "IPv6: use Block address" : canClose ? "Close this connection now" : a?.reason}
      onClick={() => act(key, `Close ${c.program}'s connection to ${c.remote}:${c.remotePort}?\n\n`
        + "The program may connect again - use Block address to stop it for good.", () => closeConnection(c))}>
      Close
    </button>
  );

  const blockAddrBtn = (c: PcConnection, key: string) => blockedAddrs.has(c.remote) ? (
    <span className="text-[11px] text-red-300">blocked</span>
  ) : (
    <button className={BTN_RED} disabled={!canFirewall || busy !== "" || !c.outside}
      title={!c.outside ? "Only internet addresses can be blocked here" : canFirewall ? "Block this address in Windows Firewall" : a?.reason}
      onClick={() => act(key, `Block ${c.remote}${c.owner ? ` (${c.owner})` : ""} in Windows Firewall?\n\n`
        + "No program on this PC can reach it until you press Unblock.", () => blockAddress(c.remote))}>
      Block address
    </button>
  );

  return (
    <div>
      <PageHeader
        title="PC Network"
        subtitle="Which ports of this computer are open or closed, which programs are talking to which computers right now - and the buttons to block, close or end them."
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
      {a && a.reason && (
        <p className="text-xs text-amber-300 mb-4 rounded-md border border-amber-500/30 bg-amber-500/5 p-2">{a.reason}</p>
      )}

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
                    <div className="mt-2 flex flex-wrap gap-2">
                      {f.port && !f.remote && !blockedPorts.has(f.port) && (
                        <button className={BTN_RED} disabled={!canFirewall || busy !== ""} title={canFirewall ? "" : a?.reason}
                          onClick={() => act(`f-port-${i}`, `Block port ${f.port} in Windows Firewall?\n\nOther computers can no longer connect to it; `
                            + "this PC itself still can. Press Unblock to undo.", () => blockPort(f.port as number))}>
                          Block port {f.port}
                        </button>
                      )}
                      {f.remote && !blockedAddrs.has(f.remote) && (
                        <button className={BTN_RED} disabled={!canFirewall || busy !== ""} title={canFirewall ? "" : a?.reason}
                          onClick={() => act(`f-addr-${i}`, `Block ${f.remote} in Windows Firewall?`, () => blockAddress(f.remote as string))}>
                          Block {f.remote}
                        </button>
                      )}
                      {f.pid ? endBtn(f.pid, f.program ?? "", `f-end-${i}`, f.canEnd) : null}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </CardBody>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader title="Port status: open or closed"
            subtitle="Important ports of this computer. OPEN = a program waits for connections there; CLOSED = nothing listens, nobody can connect."
            icon={<ICONS.lock size={16} />}
            action={<label className="flex items-center gap-1 text-[11px] text-slate-400"><input type="checkbox" checked={showClosed} onChange={(e) => setShowClosed(e.target.checked)} /> show closed</label>} />
          <CardBody>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead><tr className="text-left text-slate-500"><th className="py-1 pr-2">Port</th><th className="pr-2">Service</th><th className="pr-2">State</th><th className="pr-2">Reachable from</th><th className="pr-2">Program</th><th>Action</th></tr></thead>
                <tbody>
                  {ports.map((p) => (
                    <tr key={p.port} className="border-t border-default">
                      <td className="py-1 pr-2 font-mono text-slate-200">{p.port}</td>
                      <td className="pr-2 text-slate-400">{p.service || "-"}</td>
                      <td className="pr-2">
                        <span className={`rounded border px-1.5 py-0.5 text-[11px] uppercase ${p.state === "open" ? RISK[p.risk] : RISK.low}`}>
                          {p.state}{blockedPorts.has(p.port) ? " · blocked" : ""}
                        </span>
                      </td>
                      <td className={`pr-2 ${SCOPE[p.scope] ?? "text-slate-500"}`}>{p.scope || "-"}</td>
                      <td className="pr-2 text-slate-300">{p.program ? `${p.program} (${p.pid})` : "-"}</td>
                      <td className="flex gap-1 py-1">
                        {p.state === "open" && p.scope !== "this computer only" && !blockedPorts.has(p.port) && (
                          <button className={BTN_RED} disabled={!canFirewall || busy !== ""} title={canFirewall ? "Block other computers from this port" : a?.reason}
                            onClick={() => act(`p-${p.port}`, `Block port ${p.port}${p.service ? ` (${p.service})` : ""} in Windows Firewall?\n\n`
                              + "Other computers can no longer connect to it; this PC itself still can. Press Unblock to undo.", () => blockPort(p.port))}>
                            Block port
                          </button>
                        )}
                        {p.state === "open" && endBtn(p.pid, p.program, `pe-${p.port}`, p.canEnd)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardBody>
        </Card>

        <Card>
          <CardHeader title="All open ports" subtitle="Every program waiting for connections, and who can reach it" icon={<ICONS.server size={16} />} />
          <CardBody>
            <div className="overflow-x-auto max-h-96 overflow-y-auto">
              <table className="w-full text-xs">
                <thead><tr className="text-left text-slate-500"><th className="py-1 pr-2">Port</th><th className="pr-2">Program</th><th className="pr-2">Reachable from</th><th className="pr-2">Service</th><th>Action</th></tr></thead>
                <tbody>
                  {(snap?.listening ?? []).map((l) => (
                    <tr key={`${l.protocol}-${l.address}-${l.port}`} className="border-t border-default">
                      <td className="py-1 pr-2 font-mono text-slate-200">{l.protocol} {l.port}</td>
                      <td className="pr-2 text-slate-300">{l.program}{l.pid ? <span className="text-slate-500"> ({l.pid})</span> : null}</td>
                      <td className={`pr-2 ${SCOPE[l.scope] ?? "text-slate-400"}`}>{l.scope}</td>
                      <td className="pr-2 text-slate-400">{l.service || "-"}</td>
                      <td className="py-1">
                        {l.scope !== "this computer only" && !blockedPorts.has(l.port) ? (
                          <button className={BTN_RED} disabled={!canFirewall || busy !== ""} title={canFirewall ? "Block other computers from this port" : a?.reason}
                            onClick={() => act(`l-${l.protocol}-${l.port}`, `Block ${l.protocol} port ${l.port} in Windows Firewall?\n\n`
                              + "Other computers can no longer connect to it; this PC itself still can. Press Unblock to undo.",
                              () => blockPort(l.port, l.protocol))}>
                            Block
                          </button>
                        ) : blockedPorts.has(l.port) ? <span className="text-[11px] text-red-300">blocked</span> : null}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardBody>
        </Card>

        <Card>
          <CardHeader title="Blocked by CyberGuard" subtitle="Windows Firewall rules made from this page - remove one to undo it" icon={<ICONS.shieldX size={16} />} />
          <CardBody>
            {(snap?.blocked ?? []).length === 0 ? <p className="text-xs text-slate-500">Nothing blocked.</p> : (
              <ul className="space-y-2">
                {(snap?.blocked ?? []).map((b) => (
                  <li key={b.name} className="flex items-center justify-between gap-2 rounded-md border border-default p-2">
                    <div>
                      <p className="text-xs text-slate-200">{b.kind === "port" ? `Port ${b.protocol} ${b.port} (incoming)` : `Address ${b.address} (in + out)`}</p>
                      <p className="text-[11px] text-slate-500">since {new Date(b.at).toLocaleString()}</p>
                    </div>
                    <button className={BTN_CYAN} disabled={!canFirewall || busy !== ""} title={canFirewall ? "" : a?.reason}
                      onClick={() => act(`u-${b.name}`, `Remove the firewall rule "${b.name}"?`, () => unblock(b.name))}>
                      Unblock
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </CardBody>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader title="Live connections" subtitle={`${conns.length} shown${snap?.truncated ? " (first 500)" : ""}`} icon={<ICONS.wifi size={16} />}
            action={
              <div className="flex items-center gap-3">
                <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter: program, address, owner…"
                  className="rounded border border-default bg-transparent px-2 py-1 text-[11px] text-slate-200 w-48" />
                <label className="flex items-center gap-1 text-[11px] text-slate-400"><input type="checkbox" checked={internetOnly} onChange={(e) => setInternetOnly(e.target.checked)} /> internet only</label>
              </div>
            } />
          <CardBody>
            <details className="mb-3 text-xs text-slate-400">
              <summary className="cursor-pointer text-cyan-300">What do these columns mean?</summary>
              <ul className="mt-2 space-y-1 list-disc pl-4">
                <li><b>Program</b>: the program on this PC that owns the connection (its process id in brackets - the same number Task Manager &gt; Details shows).</li>
                <li><b>Remote address</b>: the OTHER computer this program is talking to - its IP address and port. The port tells the kind of service (443 = secure web, 80 = web, 53 = name look-up, 5228 = Google notifications). Below it: the name that computer's owner gave it, the organisation, and whether it is on the internet or your own network.</li>
                <li><b>State</b>: {Object.entries(meaning).filter(([k]) => ["ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT", "SYN_SENT"].includes(k)).map(([k, v]) => `${k.toLowerCase().replace("_", " ")} = ${v}`).join("; ")}.</li>
                <li><b>Close</b> ends that one connection now (the program may reconnect). <b>Block address</b> stops every program on this PC from reaching that address (undo under "Blocked by CyberGuard"). <b>End program</b> closes the whole program.</li>
              </ul>
            </details>
            <div className="overflow-x-auto max-h-[28rem] overflow-y-auto">
              <table className="w-full text-xs">
                <thead><tr className="text-left text-slate-500"><th className="py-1 pr-2">Program</th><th className="pr-2">Remote address (the other computer)</th><th className="pr-2">State</th><th>Actions</th></tr></thead>
                <tbody>
                  {conns.map((c, i) => {
                    const key = `${c.local}-${c.remote}-${c.remotePort}-${i}`;
                    return (
                      <tr key={key} className="border-t border-default align-top">
                        <td className="py-1 pr-2 text-slate-300">{c.program}{c.pid ? <span className="text-slate-500"> ({c.pid})</span> : null}</td>
                        <td className="py-1 pr-2">
                          <span className="font-mono text-slate-200">{c.remote}:{c.remotePort}</span>
                          {blockedAddrs.has(c.remote) && <span className="ml-1 text-[11px] text-red-300">blocked</span>}
                          <div className="text-[11px] text-slate-500">
                            {[c.owner, c.remoteName && c.remoteName !== c.owner ? c.remoteName : "", c.remoteService, c.where]
                              .filter(Boolean).join(" · ")}
                          </div>
                        </td>
                        <td className="py-1 pr-2 text-slate-400" title={meaning[c.status] ?? ""}>{c.status.toLowerCase().replace("_", " ")}</td>
                        <td className="py-1">
                          <div className="flex flex-wrap gap-1">
                            {c.status === "ESTABLISHED" && closeBtn(c, `c-${key}`)}
                            {blockAddrBtn(c, `b-${key}`)}
                            {endBtn(c.pid, c.program, `e-${key}`, c.canEnd)}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
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
