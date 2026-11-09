import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/layout/PageHeader";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { AdminOnlyCard } from "@/components/settings/AdminOnlyCard";
import { ApiError } from "@/services/api/client";
import { companyService, type Employee, type EmployeeDetail, type EmployeesResponse, type Invite } from "@/services/api/companyService";
import { useToast } from "@/context/ToastContext";
import { formatRelativeTime } from "@/lib/utils";
import { ICONS } from "@/lib/icons";
import { cn } from "@/lib/utils";

function Stat({ label, value, hint, tone }: { label: string; value: number | string; hint?: string; tone?: string }) {
  return (
    <div className="rounded-lg border border-default bg-elevated/40 p-3">
      <p className="text-[11px] uppercase tracking-wide text-slate-500">{label}</p>
      <p className={cn("text-2xl font-bold mt-1", tone ?? "text-white")}>{value}</p>
      {hint && <p className="text-[11px] text-slate-500 mt-0.5">{hint}</p>}
    </div>
  );
}

function Pill({ children, className }: { children: React.ReactNode; className?: string }) {
  return <span className={cn("text-[10px] font-semibold uppercase tracking-wide rounded px-1.5 py-0.5 border", className)}>{children}</span>;
}

const seen = (iso: string | null) => (iso ? formatRelativeTime(iso) : "never");
const RISK = (r: number) => (r >= 86 ? "text-red-400" : r >= 71 ? "text-orange-400" : r >= 51 ? "text-amber-400" : "text-emerald-400");

/** (9 Nov) Company mode: everyone who uses this CyberGuard, their activity, and the administrator's controls. */
export default function Employees() {
  const { notify } = useToast();
  const [data, setData] = useState<EmployeesResponse | null>(null);
  const [invites, setInvites] = useState<Invite[]>([]);
  const [adminOnly, setAdminOnly] = useState(false);
  const [error, setError] = useState("");
  const [detail, setDetail] = useState<EmployeeDetail | null>(null);
  const [confirm, setConfirm] = useState<string>("");       // "<action>:<id>" waiting for a second click
  const [busy, setBusy] = useState("");
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<"employee" | "admin">("employee");
  const [lastInvite, setLastInvite] = useState<Invite | null>(null);

  const load = useCallback(() =>
    Promise.all([companyService.employees(), companyService.invites()]).then(([e, i]) => {
      setData(e);
      setInvites(i.invites);
      setError("");
    }).catch((e) => {
      if (e instanceof ApiError && e.status === 403) setAdminOnly(true);
      else setError(e instanceof Error ? e.message : "Could not load the employee list.");
    }), []);

  useEffect(() => {
    load();
    const t = window.setInterval(load, 30000);
    return () => window.clearInterval(t);
  }, [load]);

  useEffect(() => {                                         // show the activity card that was just opened
    if (detail) document.getElementById("employee-activity")?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [detail]);

  useEffect(() => {
    if (!confirm) return;
    const t = window.setTimeout(() => setConfirm(""), 4000);
    return () => window.clearTimeout(t);
  }, [confirm]);

  async function act(key: string, run: () => Promise<unknown>, done: string) {
    if (confirm !== key) {                                  // first click asks, second click does it
      setConfirm(key);
      return;
    }
    setConfirm("");
    setBusy(key);
    try {
      await run();
      notify({ variant: "success", title: done });
      await load();
    } catch (e) {
      notify({ variant: "critical", title: "Not changed", description: e instanceof Error ? e.message : "Please try again." });
    } finally {
      setBusy("");
    }
  }

  async function sendInvite(e: React.FormEvent) {
    e.preventDefault();
    if (!email.trim()) return;
    setBusy("invite");
    try {
      const inv = await companyService.invite(email.trim(), role);
      setLastInvite(inv);
      setEmail("");
      notify({ variant: "success", title: "Invite created", description: inv.emailStatus === "sent" ? `E-mail sent to ${inv.email}` : "Share the link below with them." });
      await load();
    } catch (err) {
      notify({ variant: "critical", title: "Could not invite", description: err instanceof Error ? err.message : "Please try again." });
    } finally {
      setBusy("");
    }
  }

  async function openDetail(emp: Employee) {
    if (detail?.id === emp.id) {
      setDetail(null);
      return;
    }
    try {
      setDetail(await companyService.employee(emp.id));
    } catch (e) {
      notify({ variant: "critical", title: "Could not load", description: e instanceof Error ? e.message : "" });
    }
  }

  if (adminOnly) {
    return (
      <div>
        <PageHeader title="Employees" subtitle="Everyone who uses the company's CyberGuard." />
        <AdminOnlyCard title="Employees" what="The company's people, their sign-ins, scans and threats" />
      </div>
    );
  }

  const s = data?.summary;
  const company = data?.company;
  const openInvites = invites.filter((i) => i.status === "open");

  return (
    <div className="space-y-6">
      <PageHeader
        title="Employees"
        subtitle={`Everyone who uses ${company?.name || "the company"}'s CyberGuard: who is online, their sign-ins, scans and threats. Every employee uses all detection modules for their own protection; administrators also see this page.`}
        action={<Button variant="outline" size="sm" onClick={() => load()}><ICONS.refresh size={14} /> Refresh</Button>}
      />
      {error && <p className="text-sm text-red-400" role="alert">{error}</p>}

      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <Stat label="People" value={s?.total ?? "–"} />
        <Stat label="Online now" value={s?.online ?? "–"} tone="text-emerald-400" hint="active in the last 5 min" />
        <Stat label="Administrators" value={s?.admins ?? "–"} />
        <Stat label="Threats found" value={s?.threats ?? "–"} tone={s?.threats ? "text-orange-400" : undefined} hint="high risk + critical scans" />
        <Stat label="Open invites" value={s?.openInvites ?? "–"} />
        <Stat label="Disabled" value={s?.disabled ?? "–"} tone={s?.disabled ? "text-amber-400" : undefined} />
      </div>

      <Card>
        <CardHeader title="Invite someone" icon={<ICONS.send size={16} />}
          subtitle={company?.domains.length
            ? `People with ${company.domains.map((d) => "@" + d).join(", ")} e-mails can join by themselves. Anyone else (e.g. a judge or contractor) needs an invite.`
            : "Sign-up is open to everyone on this server (no company domain set), so invites are optional."} />
        <CardBody>
          <form onSubmit={sendInvite} className="flex flex-col sm:flex-row gap-2">
            <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} placeholder="name@example.com"
              aria-label="E-mail address to invite"
              className="flex-1 rounded-lg border border-strong bg-elevated px-3 py-2 text-sm text-white placeholder:text-slate-500 focus-ring" />
            <select value={role} onChange={(e) => setRole(e.target.value as "employee" | "admin")} aria-label="Role"
              className="rounded-lg border border-strong bg-elevated px-3 py-2 text-sm text-white focus-ring">
              <option value="employee">Employee</option>
              <option value="admin">Administrator</option>
            </select>
            <Button type="submit" disabled={busy === "invite"}>{busy === "invite" ? "Inviting…" : "Invite"}</Button>
          </form>
          {lastInvite?.link && (
            <p className="text-xs text-slate-400 mt-3 break-all">
              Invite link for {lastInvite.email} (valid until {lastInvite.expiresAt ? new Date(lastInvite.expiresAt).toLocaleDateString() : "–"}):{" "}
              <span className="text-cyan-300">{lastInvite.link}</span>
              {lastInvite.emailStatus !== "sent" && " — e-mail is not set up on this server, so send them this link yourself."}
            </p>
          )}
          {openInvites.length > 0 && (
            <ul className="mt-4 divide-y divide-[var(--border-default,#1e293b)] text-sm">
              {openInvites.map((i) => (
                <li key={i.id} className="flex items-center justify-between gap-3 py-2">
                  <span className="min-w-0 truncate text-slate-300">{i.email} <span className="text-slate-500">· {i.role} · until {i.expiresAt ? new Date(i.expiresAt).toLocaleDateString() : "–"}</span></span>
                  <Button variant="ghost" size="sm" disabled={busy === `revoke:${i.id}`}
                    onClick={() => act(`revoke:${i.id}`, () => companyService.revokeInvite(i.id), `Invite for ${i.email} withdrawn`)}>
                    {confirm === `revoke:${i.id}` ? "Click again to withdraw" : "Withdraw"}
                  </Button>
                </li>
              ))}
            </ul>
          )}
        </CardBody>
      </Card>

      <Card>
        <CardHeader title="People" icon={<ICONS.contact size={16} />}
          subtitle="Refreshes every 30 seconds. Disabling an account signs it out everywhere at once; nothing is deleted." />
        <CardBody className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-sm min-w-[880px]">
              <thead>
                <tr className="text-left text-[11px] uppercase tracking-wide text-slate-500 border-b border-default">
                  <th className="px-4 py-2.5 font-medium">Person</th>
                  <th className="px-3 py-2.5 font-medium">Last active</th>
                  <th className="px-3 py-2.5 font-medium">Scans · threats</th>
                  <th className="px-3 py-2.5 font-medium">Failed sign-ins (7 days)</th>
                  <th className="px-3 py-2.5 font-medium">PCs</th>
                  <th className="px-4 py-2.5 font-medium text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {(data?.employees ?? []).map((e) => {
                  const me = e.id === data?.you;
                  const locked = me || e.owner;
                  return (
                    <tr key={e.id} className={cn("border-b border-default align-top", !e.active && "opacity-60")}>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <span className={cn("h-2 w-2 rounded-full shrink-0", e.online ? "bg-emerald-400" : "bg-slate-600")} title={e.online ? "online now" : "offline"} />
                          <span className="font-medium text-white truncate">{e.name}</span>
                          {me && <Pill className="border-cyan-500/40 text-cyan-300">You</Pill>}
                          {e.role === "admin" && <Pill className="border-violet-500/40 text-violet-300">{e.owner ? "Owner" : "Admin"}</Pill>}
                          {!e.active && <Pill className="border-amber-500/40 text-amber-300">Disabled</Pill>}
                        </div>
                        <p className="text-xs text-slate-500 mt-0.5 ml-4 truncate">{e.email} · {e.signIn}</p>
                      </td>
                      <td className="px-3 py-3 text-xs text-slate-400">
                        <p>{e.online ? <span className="text-emerald-400">online now</span> : seen(e.lastSeen)}</p>
                        <p className="text-slate-500">{[e.lastIp, e.lastBrowser].filter(Boolean).join(" · ") || "–"}</p>
                      </td>
                      <td className="px-3 py-3 text-xs">
                        <span className="text-white">{e.scans}</span>
                        <span className="text-slate-500"> · </span>
                        <span className={e.threats ? "text-orange-400 font-semibold" : "text-slate-400"}>{e.threats}</span>
                        <p className="text-slate-500">{e.lastScan ? `last ${seen(e.lastScan)}` : "no scans yet"}</p>
                      </td>
                      <td className={cn("px-3 py-3 text-xs", e.failedSignIns7d >= 5 ? "text-red-400 font-semibold" : "text-slate-400")}>{e.failedSignIns7d}</td>
                      <td className="px-3 py-3 text-xs text-slate-400">{e.devices}</td>
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap justify-end gap-1.5">
                          <Button variant="outline" size="sm" onClick={() => openDetail(e)}>{detail?.id === e.id ? "Hide" : "Activity"}</Button>
                          {!locked && (
                            <>
                              <Button variant="ghost" size="sm" disabled={!!busy}
                                onClick={() => act(`role:${e.id}`, () => companyService.setRole(e.id, e.role === "admin" ? "employee" : "admin"),
                                  e.role === "admin" ? `${e.name} is now an employee` : `${e.name} is now an administrator`)}>
                                {confirm === `role:${e.id}` ? "Click to confirm" : e.role === "admin" ? "Remove admin" : "Make admin"}
                              </Button>
                              <Button variant="ghost" size="sm" disabled={!!busy || !e.active}
                                onClick={() => act(`out:${e.id}`, () => companyService.signOut(e.id), `${e.name} was signed out everywhere`)}>
                                {confirm === `out:${e.id}` ? "Click to confirm" : "Sign out"}
                              </Button>
                              <Button variant={e.active ? "ghost" : "outline"} size="sm" disabled={!!busy}
                                className={e.active ? "text-red-300 hover:text-red-200" : undefined}
                                onClick={() => act(`active:${e.id}`, () => companyService.setActive(e.id, !e.active),
                                  e.active ? `${e.name} was disabled` : `${e.name} was enabled again`)}>
                                {confirm === `active:${e.id}` ? "Click to confirm" : e.active ? "Disable" : "Enable"}
                              </Button>
                            </>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {data && data.employees.length === 0 && <p className="p-4 text-sm text-slate-500">Nobody has joined yet.</p>}
        </CardBody>
      </Card>

      {detail && (
        <Card id="employee-activity">
          <CardHeader title={`Activity of ${detail.name}`} subtitle={`${detail.email} · newest first`} icon={<ICONS.scanHistory size={16} />}
            action={<Button variant="ghost" size="sm" onClick={() => setDetail(null)}>Close</Button>} />
          <CardBody className="grid lg:grid-cols-2 gap-6">
            <div>
              <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 mb-2">Scans</p>
              {detail.scans.length === 0 ? <p className="text-sm text-slate-500">No scans yet.</p> : (
                <ul className="space-y-2">
                  {detail.scans.map((x) => (
                    <li key={x.id} className="text-xs">
                      <span className={cn("font-semibold", RISK(x.risk))}>{x.risk}</span>
                      <span className="text-slate-300"> · {x.subtopic}</span>
                      {x.source.startsWith("agent") && <span className="text-cyan-400"> · from a PC agent</span>}
                      <span className="text-slate-500"> · {x.at ? seen(x.at) : ""}</span>
                      <p className="text-slate-500 truncate">{x.target}</p>
                    </li>
                  ))}
                </ul>
              )}
            </div>
            <div>
              <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 mb-2">Sign-ins</p>
              {detail.signIns.length === 0 ? <p className="text-sm text-slate-500">No sign-ins recorded.</p> : (
                <ul className="space-y-2">
                  {detail.signIns.map((x, n) => (
                    <li key={n} className="text-xs">
                      <span className={x.success ? "text-emerald-400" : "text-red-400"}>{x.success ? "✓" : "✗"}</span>
                      <span className="text-slate-300"> {x.action.replace("auth.", "").replace(/_/g, " ")}</span>
                      <span className="text-slate-500"> · {[x.ip, x.browser].filter(Boolean).join(" · ")} · {x.at ? seen(x.at) : ""}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </CardBody>
        </Card>
      )}
    </div>
  );
}
