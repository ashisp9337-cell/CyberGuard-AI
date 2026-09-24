import { useEffect, useState } from "react";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { CircularScore } from "@/components/ui/Progress";
import { fetchOverview, overviewToSecurityScoreSnapshot, type DashboardOverview } from "@/services/api/dashboardService";
import { ICONS } from "@/lib/icons";

export function SecurityScoreCard() {
  const [overview, setOverview] = useState<DashboardOverview | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchOverview().then((o) => !cancelled && setOverview(o)).catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  if (!overview) {
    return (
      <Card>
        <CardHeader title="Overall Security Score" icon={<ICONS.shieldCheck size={16} />} />
        <CardBody className="flex items-center justify-center py-10 text-sm text-fg-muted">Loading…</CardBody>
      </Card>
    );
  }

  const snap = overviewToSecurityScoreSnapshot(overview);
  const rows = [
    { label: "Critical", value: snap.critical, color: "var(--color-critical)" },
    { label: "High", value: snap.high, color: "var(--color-high)" },
    { label: "Medium", value: snap.medium, color: "var(--color-warning)" },
    { label: "Low", value: snap.low, color: "var(--color-safe)" },
  ];
  const STATUS_STYLE: Record<string, string> = {
    PROTECTED: "bg-emerald-500/10 text-emerald-400",
    "AT RISK": "bg-amber-500/10 text-amber-400",
    CRITICAL: "bg-red-500/10 text-red-400",
  };
  const STATUS_DOT: Record<string, string> = {
    PROTECTED: "bg-emerald-400",
    "AT RISK": "bg-amber-400",
    CRITICAL: "bg-red-400",
  };
  return (
    <Card>
      <CardHeader title="Overall Security Score" icon={<ICONS.shieldCheck size={16} />} />
      <CardBody className="flex flex-col items-center gap-4">
        <CircularScore value={snap.score} label="/ 100" color="var(--color-safe)" />
        <span className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-bold tracking-wide uppercase ${STATUS_STYLE[snap.status] ?? STATUS_STYLE.PROTECTED}`}>
          <span className={`h-1.5 w-1.5 rounded-full ${STATUS_DOT[snap.status] ?? STATUS_DOT.PROTECTED}`} /> {snap.status}
        </span>
        <div className="w-full grid grid-cols-2 gap-2 pt-2 border-t border-default mt-1">
          {rows.map((r) => (
            <div key={r.label} className="flex items-center justify-between rounded-lg bg-elevated px-2.5 py-2">
              <span className="flex items-center gap-1.5 text-xs text-slate-400">
                <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: r.color }} />
                {r.label}
              </span>
              <span className="text-xs font-bold text-white">{r.value}</span>
            </div>
          ))}
        </div>
      </CardBody>
    </Card>
  );
}
