import { useEffect, useState } from "react";
import { PageHeader } from "@/components/layout/PageHeader";
import { StatCard } from "@/components/dashboard/StatCard";
import { SecurityScoreCard } from "@/components/dashboard/SecurityScoreCard";
import { ThreatActivityChart } from "@/components/charts/ThreatActivityChart";
import { ThreatDistributionChart } from "@/components/charts/ThreatDistributionChart";
import { LiveThreatFeed } from "@/components/dashboard/LiveThreatFeed";
import { QuickActions } from "@/components/dashboard/QuickActions";
import { TopTargetsCard } from "@/components/dashboard/TopTargetsCard";
import { IncidentsCard } from "@/components/dashboard/IncidentsCard";
import { QuarantineCard } from "@/components/dashboard/QuarantineCard";
import { fetchOverview, type DashboardOverview } from "@/services/api/dashboardService";
import { listReports } from "@/services/api/reportsService";
import { ICONS } from "@/lib/icons";

export default function Dashboard() {
  const [overview, setOverview] = useState<DashboardOverview | null>(null);
  const [reportCount, setReportCount] = useState<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchOverview().then((o) => !cancelled && setOverview(o)).catch(() => {});
    listReports().then((r) => !cancelled && setReportCount(r.length)).catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div>
      <PageHeader
        title="Security Overview"
        subtitle="Real-time AI-powered analysis of digital threats, suspicious activity, malware indicators, and security risks."
      />

      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4 mb-5">
        <StatCard label="Active Threats" value={overview?.activeThreats ?? "—"} icon={<ICONS.threatOverview size={16} />} accent="var(--color-critical)">
          <div className="flex gap-2 text-[10px] pt-1">
            <span className="text-red-400">Critical {overview?.critical ?? 0}</span>
            <span className="text-orange-400">High {overview?.high ?? 0}</span>
            <span className="text-yellow-400">Med {overview?.medium ?? 0}</span>
            <span className="text-emerald-400">Low {overview?.low ?? 0}</span>
          </div>
        </StatCard>
        <StatCard label="Total Scans Run" value={overview?.totalScans ?? "—"} icon={<ICONS.scan size={16} />} accent="var(--color-brand)" />
        <StatCard label="Critical Threats" value={overview?.criticalThreats ?? "—"} icon={<ICONS.warning size={16} />} accent="var(--color-warning)" />
        <StatCard label="Reports Generated" value={reportCount ?? "—"} icon={<ICONS.reports size={16} />} accent="var(--color-info)" />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5 mb-5">
        <div className="xl:col-span-2 space-y-5">
          <ThreatActivityChart />
          <IncidentsCard />
          <QuickActions />
        </div>
        <div className="space-y-5">
          <SecurityScoreCard />
          <ThreatDistributionChart />
          <TopTargetsCard />
          <QuarantineCard />
        </div>
      </div>

      <LiveThreatFeed limit={8} />
    </div>
  );
}
