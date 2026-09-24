import { useMemo, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { PageHeader } from "@/components/layout/PageHeader";
import { Card, CardBody } from "@/components/ui/Card";
import { SeverityBadge } from "@/components/ui/Badge";
import { TextInput } from "@/components/ui/Input";
import { useAppContext } from "@/context/AppContext";
import { DETECTION_MODULES } from "@/data/modules";
import { formatDate } from "@/lib/utils";
import { ICONS } from "@/lib/icons";
import type { Severity } from "@/types";

const STATUS_META: Record<string, { label: string; color: string }> = {
  completed: { label: "Completed", color: "var(--color-info)" },
  flagged: { label: "Flagged", color: "var(--color-critical)" },
  cleared: { label: "Cleared", color: "var(--color-safe)" },
  escalated: { label: "Escalated", color: "var(--color-high)" },
};

export default function ScanHistory() {
  const { scanHistory } = useAppContext();
  const location = useLocation();
  const navigate = useNavigate();
  const [search, setSearch] = useState((location.state as any)?.search ?? "");
  const [moduleFilter, setModuleFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState<"all" | Severity>("all");
  const [sortDesc, setSortDesc] = useState(true);

  const filtered = useMemo(() => {
    let rows = scanHistory.filter((r) => {
      const matchesSearch = !search || r.target.toLowerCase().includes(search.toLowerCase()) || r.threatType.toLowerCase().includes(search.toLowerCase());
      const matchesModule = moduleFilter === "all" || r.moduleId === moduleFilter;
      const matchesSeverity = severityFilter === "all" || r.severity === severityFilter;
      return matchesSearch && matchesModule && matchesSeverity;
    });
    rows = rows.sort((a, b) => (sortDesc ? (a.date < b.date ? 1 : -1) : a.date < b.date ? -1 : 1));
    return rows;
  }, [scanHistory, search, moduleFilter, severityFilter, sortDesc]);

  return (
    <div>
      <PageHeader title="Scan History" subtitle="Browse, search, and filter every scan performed across the platform." />

      <Card className="mb-5">
        <CardBody className="flex flex-col md:flex-row gap-3">
          <div className="flex-1">
            <TextInput
              placeholder="Search by target or threat type..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              aria-label="Search scan history"
            />
          </div>
          <select
            value={moduleFilter}
            onChange={(e) => setModuleFilter(e.target.value)}
            aria-label="Filter by module"
            className="rounded-lg bg-elevated border border-strong px-3 py-2.5 text-sm text-white focus-ring"
          >
            <option value="all">All Modules</option>
            {DETECTION_MODULES.map((m) => (
              <option key={m.id} value={m.id}>{m.shortName}</option>
            ))}
          </select>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value as any)}
            aria-label="Filter by severity"
            className="rounded-lg bg-elevated border border-strong px-3 py-2.5 text-sm text-white focus-ring"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <button
            onClick={() => setSortDesc((v) => !v)}
            className="flex items-center gap-1.5 rounded-lg bg-elevated border border-strong px-3 py-2.5 text-sm text-slate-300 hover:text-white focus-ring shrink-0"
          >
            <ICONS.filter size={14} /> {sortDesc ? "Newest" : "Oldest"}
          </button>
        </CardBody>
      </Card>

      <Card>
        <CardBody className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-default text-left text-xs text-slate-500 uppercase tracking-wide">
                  <th className="px-4 py-3 font-medium">Scan ID</th>
                  <th className="px-4 py-3 font-medium">Target</th>
                  <th className="px-4 py-3 font-medium">Threat Type</th>
                  <th className="px-4 py-3 font-medium">Risk Score</th>
                  <th className="px-4 py-3 font-medium">Severity</th>
                  <th className="px-4 py-3 font-medium">Date</th>
                  <th className="px-4 py-3 font-medium">Status</th>
                  <th className="px-4 py-3 font-medium sr-only">Action</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((r) => {
                  const mod = DETECTION_MODULES.find((m) => m.id === r.moduleId);
                  const statusMeta = STATUS_META[r.status];
                  return (
                    <tr
                      key={r.scanId}
                      className="border-b border-default hover:bg-elevated transition-colors cursor-pointer"
                      onClick={() => mod && navigate(`/modules/${mod.id}`)}
                    >
                      <td className="px-4 py-3 mono text-xs text-slate-400">{r.scanId}</td>
                      <td className="px-4 py-3 text-slate-200 max-w-[200px] truncate mono text-xs">{r.target}</td>
                      <td className="px-4 py-3 text-slate-300">{r.threatType}</td>
                      <td className="px-4 py-3 font-mono text-slate-300">{r.riskScore}</td>
                      <td className="px-4 py-3"><SeverityBadge severity={r.severity} size="sm" /></td>
                      <td className="px-4 py-3 text-slate-500 text-xs whitespace-nowrap">{formatDate(r.date)}</td>
                      <td className="px-4 py-3">
                        <span className="text-xs font-medium" style={{ color: statusMeta.color }}>{statusMeta.label}</span>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <ICONS.chevronRight size={15} className="text-slate-600" />
                      </td>
                    </tr>
                  );
                })}
                {filtered.length === 0 && (
                  <tr>
                    <td colSpan={8} className="px-4 py-10 text-center text-sm text-slate-500">No scans match your filters.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </CardBody>
      </Card>
    </div>
  );
}
