import { useEffect, useState } from "react";
import { PageHeader } from "@/components/layout/PageHeader";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { ThreatDistributionChart } from "@/components/charts/ThreatDistributionChart";
import { SeverityBadge } from "@/components/ui/Badge";
import { listScans } from "@/services/api/scansService";
import { fetchThreatDistribution } from "@/services/api/dashboardService";
import { formatRelativeTime } from "@/lib/utils";
import { ICONS } from "@/lib/icons";
import type { ThreatDistributionSlice, ScanHistoryEntry } from "@/types";

// No geolocation/IP-intelligence pipeline is implemented in this build, so
// regional activity can't be backed by real data — shown as clearly-labeled
// illustrative demo content rather than presented as live telemetry.
const DEMO_REGIONS = [
  { name: "North America", activity: 82 },
  { name: "Europe", activity: 64 },
  { name: "South Asia", activity: 91 },
  { name: "Southeast Asia", activity: 58 },
  { name: "Middle East", activity: 47 },
  { name: "South America", activity: 35 },
];

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
      <PageHeader title="Threat Intelligence" subtitle="Aggregated intelligence on emerging threats, trends, and global activity." />
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

      <Card>
        <CardHeader
          title="Global Threat Activity"
          subtitle="Demo data — this build has no geolocation/IP-intelligence pipeline"
          icon={<ICONS.threatIntel size={16} />}
        />
        <CardBody>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {DEMO_REGIONS.map((r) => (
              <div key={r.name} className="rounded-lg border border-default bg-elevated p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-white font-medium">{r.name}</span>
                  <span className="text-xs font-mono text-slate-400">{r.activity}</span>
                </div>
                <div className="h-1.5 w-full rounded-full bg-canvas overflow-hidden">
                  <div
                    className="h-full rounded-full"
                    style={{ width: `${r.activity}%`, backgroundColor: r.activity > 75 ? "var(--color-critical)" : r.activity > 50 ? "var(--color-warning)" : "var(--color-safe)" }}
                  />
                </div>
              </div>
            ))}
          </div>
        </CardBody>
      </Card>
    </div>
  );
}
