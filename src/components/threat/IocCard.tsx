import { useEffect, useState } from "react";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { useToast } from "@/context/ToastContext";
import { ICONS } from "@/lib/icons";
import { downloadIocCsv, getIocSummary, listIocs, setIocStatus, type Ioc, type IocSummary } from "@/services/api/iocService";

const TYPES: { key: string; label: string }[] = [
  { key: "", label: "All" },
  { key: "domain", label: "Domains" },
  { key: "url", label: "Links" },
  { key: "ip", label: "IPs" },
  { key: "email", label: "Senders" },
  { key: "sha256", label: "Files" },
];

function riskStyle(r: number): string {
  if (r >= 86) return "text-red-400";
  if (r >= 71) return "text-orange-400";
  if (r >= 51) return "text-amber-400";
  return "text-slate-400";
}

function ago(iso: string | null): string {
  if (!iso) return "—";
  const m = Math.round((Date.now() - new Date(iso).getTime()) / 60000);
  if (m < 60) return `${Math.max(m, 0)} min ago`;
  if (m < 1440) return `${Math.round(m / 60)} h ago`;
  return `${Math.round(m / 1440)} d ago`;
}

export function IocCard() {
  const { notify } = useToast();
  const [type, setType] = useState("");
  const [query, setQuery] = useState("");
  const [showAllowlisted, setShowAllowlisted] = useState(false);
  const [rows, setRows] = useState<Ioc[] | null>(null);
  const [summary, setSummary] = useState<IocSummary | null>(null);

  function load() {
    listIocs({ type, q: query, status: showAllowlisted ? "allowlisted" : "active" })
      .then(setRows)
      .catch(() => setRows([]));
    getIocSummary().then(setSummary).catch(() => {});
  }

  useEffect(load, [type, showAllowlisted]); // eslint-disable-line react-hooks/exhaustive-deps

  async function toggle(row: Ioc) {
    const next = row.status === "active" ? "allowlisted" : "active";
    try {
      await setIocStatus(row.id, next, next === "allowlisted" ? "Marked safe from Threat Intelligence" : "");
      notify({
        variant: "success",
        title: next === "allowlisted" ? "Marked as safe" : "Watching again",
        description: next === "allowlisted" ? `${row.value} will no longer raise risk scores.` : `${row.value} is active again.`,
      });
      load();
    } catch (err) {
      notify({ variant: "critical", title: "Could not change it", description: err instanceof Error ? err.message : "" });
    }
  }

  async function exportCsv() {
    try {
      await downloadIocCsv();
    } catch (err) {
      notify({ variant: "critical", title: "Export failed", description: err instanceof Error ? err.message : "" });
    }
  }

  return (
    <Card>
      <CardHeader
        title="Indicators of Compromise"
        subtitle="Bad links, domains, IPs, senders and files remembered from your risky scans. If one appears again, the new scan is flagged “Seen before”."
        icon={<ICONS.fingerprint size={16} />}
      />
      <CardBody>
        {summary && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
            <Stat label="Active indicators" value={summary.total} />
            <Stat label="Seen more than once" value={summary.repeat} />
            <Stat label="Domains / links" value={summary.byType.domain + summary.byType.url} />
            <Stat label="Marked safe" value={summary.allowlisted} />
          </div>
        )}

        <div className="flex flex-wrap items-center gap-2 mb-3">
          {TYPES.map((t) => (
            <button
              key={t.key}
              onClick={() => setType(t.key)}
              className={`rounded-full px-3 py-1 text-xs border focus-ring ${type === t.key ? "border-cyan-500 text-cyan-300 bg-cyan-500/10" : "border-default text-slate-400 hover:text-white"}`}
            >
              {t.label}
            </button>
          ))}
          <form
            onSubmit={(e) => {
              e.preventDefault();
              load();
            }}
            className="flex-1 min-w-[180px]"
          >
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search a domain, IP, sender…"
              aria-label="Search indicators"
              className="w-full rounded-lg border border-default bg-elevated px-3 py-1.5 text-xs text-white placeholder:text-slate-500 focus-ring"
            />
          </form>
          <label className="flex items-center gap-1.5 text-xs text-slate-400">
            <input type="checkbox" checked={showAllowlisted} onChange={(e) => setShowAllowlisted(e.target.checked)} className="accent-cyan-500" />
            Show marked safe
          </label>
          <button onClick={exportCsv} className="rounded-lg border border-cyan-500/50 text-cyan-300 px-3 py-1.5 text-xs hover:bg-cyan-500/10 focus-ring">
            Export blocklist (CSV)
          </button>
        </div>

        {rows === null ? (
          <p className="text-xs text-slate-500">Loading…</p>
        ) : rows.length === 0 ? (
          <p className="text-xs text-slate-500">
            {showAllowlisted ? "Nothing marked safe." : "No indicators yet. They are added automatically when a scan scores 51 or more."}
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-slate-500 border-b border-default">
                  <th className="py-2 pr-3 font-medium">Type</th>
                  <th className="py-2 pr-3 font-medium">Value</th>
                  <th className="py-2 pr-3 font-medium">Seen</th>
                  <th className="py-2 pr-3 font-medium">Max risk</th>
                  <th className="py-2 pr-3 font-medium">Last seen</th>
                  <th className="py-2 font-medium sr-only">Action</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.id} className="border-b border-default/60 last:border-0">
                    <td className="py-2 pr-3 text-slate-400 uppercase">{r.type === "sha256" ? "file" : r.type}</td>
                    <td className="py-2 pr-3 font-mono text-slate-200 max-w-[340px] truncate" title={r.value}>{r.value}</td>
                    <td className="py-2 pr-3 text-slate-300">{r.timesSeen}×</td>
                    <td className={`py-2 pr-3 font-medium ${riskStyle(r.maxRisk)}`}>{r.maxRisk}</td>
                    <td className="py-2 pr-3 text-slate-400">{ago(r.lastSeen)}</td>
                    <td className="py-2 text-right">
                      <button onClick={() => toggle(r)} className="text-cyan-300 hover:underline focus-ring rounded">
                        {r.status === "active" ? "Mark safe" : "Watch again"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardBody>
    </Card>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-lg border border-default bg-elevated/40 p-3">
      <p className="text-lg font-semibold text-white">{value}</p>
      <p className="text-[11px] text-slate-500">{label}</p>
    </div>
  );
}
