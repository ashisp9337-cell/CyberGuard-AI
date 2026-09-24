import { useEffect, useState } from "react";
import { PageHeader } from "@/components/layout/PageHeader";
import { ThreatActivityChart } from "@/components/charts/ThreatActivityChart";
import { ThreatDistributionChart } from "@/components/charts/ThreatDistributionChart";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { SeverityBadge, StatusPill } from "@/components/ui/Badge";
import { listScans } from "@/services/api/scansService";
import { formatRelativeTime } from "@/lib/utils";
import { ICONS } from "@/lib/icons";
import type { Threat, ScanHistoryEntry } from "@/types";

const STATUS_MAP: Record<ScanHistoryEntry["status"], Threat["status"]> = {
  escalated: "active",
  flagged: "investigating",
  cleared: "resolved",
  completed: "resolved",
};

function toThreat(s: ScanHistoryEntry): Threat {
  return {
    id: s.scanId, type: s.threatType, category: s.moduleId, severity: s.severity,
    target: s.target, riskScore: s.riskScore, status: STATUS_MAP[s.status] ?? "resolved",
    timestamp: s.date,
  };
}

export default function ThreatOverview() {
  const [threats, setThreats] = useState<Threat[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    listScans({ pageSize: 100 })
      .then(({ items }) => setThreats(items.map(toThreat)))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  return (
    <div>
      <PageHeader title="Threat Overview" subtitle="A consolidated view of all active and recent threats detected across every module." />
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-5 mb-5">
        <ThreatActivityChart />
        <ThreatDistributionChart />
      </div>
      <Card>
        <CardHeader title="All Threats" subtitle={`${threats.length} detections`} icon={<ICONS.threatOverview size={16} />} />
        <CardBody className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-default text-left text-xs text-slate-500 uppercase tracking-wide">
                  <th className="px-4 py-3 font-medium">Type</th>
                  <th className="px-4 py-3 font-medium">Target</th>
                  <th className="px-4 py-3 font-medium">Severity</th>
                  <th className="px-4 py-3 font-medium">Risk</th>
                  <th className="px-4 py-3 font-medium">Status</th>
                  <th className="px-4 py-3 font-medium">Detected</th>
                </tr>
              </thead>
              <tbody>
                {threats.map((t) => (
                  <tr key={t.id} className="border-b border-default hover:bg-elevated transition-colors">
                    <td className="px-4 py-3 text-slate-200 font-medium whitespace-nowrap">{t.type}</td>
                    <td className="px-4 py-3 text-slate-400 mono text-xs max-w-[220px] truncate">{t.target}</td>
                    <td className="px-4 py-3"><SeverityBadge severity={t.severity} size="sm" /></td>
                    <td className="px-4 py-3 font-mono text-slate-300">{t.riskScore}</td>
                    <td className="px-4 py-3"><StatusPill status={t.status} /></td>
                    <td className="px-4 py-3 text-slate-500 text-xs whitespace-nowrap">{formatRelativeTime(t.timestamp)}</td>
                  </tr>
                ))}
                {!loading && threats.length === 0 && (
                  <tr><td colSpan={6} className="px-4 py-10 text-center text-sm text-slate-500">No threats detected yet.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </CardBody>
      </Card>
    </div>
  );
}
