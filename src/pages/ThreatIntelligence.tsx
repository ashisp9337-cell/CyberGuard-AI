import { useEffect, useState } from "react";
import { PageHeader } from "@/components/layout/PageHeader";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { ThreatDistributionChart } from "@/components/charts/ThreatDistributionChart";
import { SeverityBadge } from "@/components/ui/Badge";
import { listScans } from "@/services/api/scansService";
import { fetchThreatDistribution } from "@/services/api/dashboardService";
import { formatRelativeTime } from "@/lib/utils";
import { ICONS } from "@/lib/icons";
import { IocCard } from "@/components/threat/IocCard";
import { MitreOverviewCard } from "@/components/mitre/MitreOverviewCard";
import { ThreatIntelLookupCard } from "@/components/threat/ThreatIntelLookupCard";
import type { ThreatDistributionSlice, ScanHistoryEntry } from "@/types";

// Latest threats, attack-type mix, and the Indicators of Compromise remembered from real scans
// (replaces the earlier illustrative "Global Threat Activity" demo, which had no real data behind it).
export default function ThreatIntelligence() {
  const [latest, setLatest] = useState<ScanHistoryEntry[]>([]);
  const [dist, setDist] = useState<ThreatDistributionSlice[]>([]);

  useEffect(() => {
    listScans({ pageSize: 6 }).then(({ items }) => setLatest(items)).catch(() => {});
    fetchThreatDistribution().then(setDist).catch(() => {});
  }, []);

  const topAttacks = [...dist].sort((a, b) => b.value - a.value);

  return (
    <div>
      <PageHeader title="Threat Intelligence" subtitle="Your latest threats, the MITRE ATT&CK techniques behind them, threat-intel lookups and the indicators CyberGuard remembers." />
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5 mb-5">
        <Card>
          <CardHeader title="Latest Threats" icon={<ICONS.radar size={16} />} />
          <CardBody className="space-y-2.5">
            {latest.length === 0 && <p className="text-sm text-slate-500 text-center py-4">No scans yet.</p>}
            {latest.map((t) => (
              <div key={t.scanId} className="flex items-start justify-between gap-2 rounded-lg bg-elevated p-3">
                <div className="min-w-0">
                  <p className="text-sm text-white font-medium truncate">{t.threatType}</p>
                  <p className="text-xs text-slate-500 mt-0.5">{formatRelativeTime(t.date)}</p>
                </div>
                <SeverityBadge severity={t.severity} size="sm" />
              </div>
            ))}
          </CardBody>
        </Card>

        <Card>
          <CardHeader title="Top Attack Types" subtitle="Share of flagged detections" icon={<ICONS.trendUp size={16} />} />
          <CardBody className="space-y-3">
            {topAttacks.length === 0 && <p className="text-sm text-slate-500 text-center py-4">No flagged detections yet.</p>}
            {topAttacks.map((a) => (
              <div key={a.name}>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-slate-300">{a.name}</span>
                  <span className="text-slate-500 font-mono">{a.value}%</span>
                </div>
                <div className="h-1.5 w-full rounded-full bg-elevated overflow-hidden">
                  <div className="h-full rounded-full" style={{ width: `${a.value}%`, backgroundColor: a.color }} />
                </div>
              </div>
            ))}
          </CardBody>
        </Card>

        <ThreatDistributionChart />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5 mb-5">
        <div className="xl:col-span-2"><MitreOverviewCard days={90} limit={8} /></div>
        <ThreatIntelLookupCard />
      </div>

      <IocCard />
    </div>
  );
}
