import { useCallback, useEffect, useState } from "react";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { SeverityBadge } from "@/components/ui/Badge";
import { useToast } from "@/context/ToastContext";
import {
  bulkUpdateIncidents, fetchIncidents, fetchIncidentSummary, updateIncidentStatus,
  type Incident, type IncidentStatus, type IncidentSummary,
} from "@/services/api/incidentsService";
import { ICONS } from "@/lib/icons";

const STATUS_META: Record<IncidentStatus, { label: string; color: string }> = {
  open: { label: "Open", color: "var(--color-critical)" },
  investigating: { label: "Investigating", color: "var(--color-warning)" },
  resolved: { label: "Resolved", color: "var(--color-safe)" },
  false_positive: { label: "False positive", color: "var(--color-info)" },
};
const ALL_STATUSES = Object.keys(STATUS_META) as IncidentStatus[];
const PAGE = 50;

function timeAgo(iso: string) {
  const mins = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 60000));
  if (mins < 60) return `${mins}m ago`;
  if (mins < 1440) return `${Math.round(mins / 60)}h ago`;
  return `${Math.round(mins / 1440)}d ago`;
}

function formatMttr(m: number | null) {
  if (m === null) return "—";
  if (m < 60) return `${Math.round(m)} min`;
  return `${(m / 60).toFixed(1)} h`;
}

export function IncidentsCard() {
  const { notify } = useToast();
  const [items, setItems] = useState<Incident[]>([]);
  const [summary, setSummary] = useState<IncidentSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [allActive, setAllActive] = useState(false);   // "every active incident", even ones not loaded

  const load = useCallback(() => {
    return Promise.all([fetchIncidents("active", PAGE), fetchIncidentSummary()])
      .then(([list, sum]) => {
        setItems(list);
        setSummary(sum);
        setSelected((prev) => new Set([...prev].filter((id) => list.some((i) => i.id === id))));
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const totalActive = summary?.active ?? items.length;
  const allLoadedSelected = items.length > 0 && items.every((i) => selected.has(i.id));
  const selectedCount = allActive ? totalActive : selected.size;

  function toggle(id: string) {
    setAllActive(false);
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleAll() {
    setAllActive(false);
    setSelected(allLoadedSelected ? new Set() : new Set(items.map((i) => i.id)));
  }

  function clearSelection() {
    setSelected(new Set());
    setAllActive(false);
  }

  async function change(item: Incident, status: IncidentStatus) {
    if (status === item.status) return;
    setBusy(item.id);
    try {
      await updateIncidentStatus(item.id, status);
      notify({ variant: "success", title: `Incident marked ${STATUS_META[status].label.toLowerCase()}` });
      await load();
    } catch (err) {
      notify({ variant: "critical", title: "Could not update incident",
               description: err instanceof Error ? err.message : "Please try again." });
    } finally {
      setBusy(null);
    }
  }

  async function applyBulk(status: IncidentStatus) {
    if (selectedCount === 0) return;
    const label = STATUS_META[status].label.toLowerCase();
    if (selectedCount > 5 && !window.confirm(`Mark ${selectedCount} incidents as ${label}?`)) return;
    setBusy("bulk");
    try {
      const res = await bulkUpdateIncidents(status, allActive ? { scope: "active" } : { ids: [...selected] });
      notify({ variant: "success", title: `${res.changed} incident${res.changed === 1 ? "" : "s"} marked ${label}` });
      clearSelection();
      await load();
    } catch (err) {
      notify({ variant: "critical", title: "Bulk update failed",
               description: err instanceof Error ? err.message : "Please try again." });
    } finally {
      setBusy(null);
    }
  }

  const stats: { label: string; value: string | number; color: string }[] = [
    { label: "Open", value: summary?.counts.open ?? "—", color: STATUS_META.open.color },
    { label: "Investigating", value: summary?.counts.investigating ?? "—", color: STATUS_META.investigating.color },
    { label: "Resolved", value: summary?.counts.resolved ?? "—", color: STATUS_META.resolved.color },
    { label: "Avg. time to resolve", value: formatMttr(summary?.mttrMinutes ?? null), color: "var(--color-fg)" },
  ];

  return (
    <Card>
      <CardHeader title="Incidents" subtitle="High and critical threats — track them until they are resolved"
                  icon={<ICONS.critical size={16} />} />
      <CardBody>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-4">
          {stats.map((s) => (
            <div key={s.label} className="rounded-lg border border-default bg-elevated px-3 py-2">
              <p className="text-[10px] uppercase tracking-wide text-fg-muted">{s.label}</p>
              <p className="text-lg font-semibold font-mono" style={{ color: s.color }}>{s.value}</p>
            </div>
          ))}
        </div>

        {!loading && items.length > 0 && (
          <div className="mb-3 rounded-lg border border-default bg-elevated px-3 py-2">
            <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
              <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer select-none">
                <input type="checkbox" checked={allLoadedSelected} onChange={toggleAll}
                       aria-label="Select all incidents" className="h-4 w-4 accent-cyan-500" />
                {selectedCount > 0 ? `${selectedCount} selected` : "Select all"}
              </label>
              {selectedCount > 0 && (
                <>
                  <span className="text-xs text-slate-500">Mark as:</span>
                  {ALL_STATUSES.map((s) => (
                    <button key={s} disabled={busy === "bulk"} onClick={() => applyBulk(s)}
                            className="rounded-md border border-default px-2.5 py-1 text-xs font-medium focus-ring disabled:opacity-50 hover:bg-surface"
                            style={{ color: STATUS_META[s].color }}>
                      {STATUS_META[s].label}
                    </button>
                  ))}
                  <button onClick={clearSelection} className="text-xs text-slate-500 hover:text-white ml-auto">Clear</button>
                </>
              )}
            </div>
            {allLoadedSelected && !allActive && totalActive > items.length && (
              <p className="mt-2 text-xs text-slate-400">
                All {items.length} shown are selected.{" "}
                <button onClick={() => setAllActive(true)} className="text-cyan-400 hover:underline">
                  Select all {totalActive} active incidents
                </button>
              </p>
            )}
          </div>
        )}

        {loading ? (
          <div className="py-8 text-center text-sm text-fg-muted">Loading…</div>
        ) : items.length === 0 ? (
          <div className="py-8 text-center text-sm text-fg-muted">No open incidents. High and critical detections appear here.</div>
        ) : (
          <ul className="space-y-2 max-h-[560px] overflow-y-auto pr-1">
            {items.map((item) => (
              <li key={item.id}
                  className="flex flex-col sm:flex-row sm:items-center gap-3 rounded-lg border bg-elevated p-3"
                  style={{ borderColor: selected.has(item.id) || allActive ? "var(--color-brand)" : "var(--color-border)" }}>
                <div className="flex items-center gap-3">
                  <input type="checkbox" checked={allActive || selected.has(item.id)} onChange={() => toggle(item.id)}
                         aria-label={`Select ${item.title}`} className="h-4 w-4 accent-cyan-500" />
                  <SeverityBadge severity={item.severity} size="sm" />
                </div>
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium text-white truncate" title={item.title}>{item.title}</p>
                  <p className="text-xs text-slate-500 truncate font-mono" title={item.target}>{item.target}</p>
                  <p className="text-[10px] text-slate-500 mt-0.5">
                    Risk {item.riskScore} · {timeAgo(item.createdAt)}
                    {item.alertedVia.length > 0 && <> · Alerted via {item.alertedVia.join(", ")}</>}
                  </p>
                </div>
                <select
                  aria-label="Incident status"
                  value={item.status}
                  disabled={busy === item.id || busy === "bulk"}
                  onChange={(e) => change(item, e.target.value as IncidentStatus)}
                  className="shrink-0 rounded-md border border-default bg-surface px-2 py-1.5 text-xs font-medium focus-ring"
                  style={{ color: STATUS_META[item.status].color }}
                >
                  {ALL_STATUSES.map((s) => (
                    <option key={s} value={s}>{STATUS_META[s].label}</option>
                  ))}
                </select>
              </li>
            ))}
          </ul>
        )}
      </CardBody>
    </Card>
  );
}
