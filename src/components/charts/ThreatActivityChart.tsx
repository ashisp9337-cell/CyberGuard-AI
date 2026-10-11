import { useEffect, useState } from "react";
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from "recharts";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { Tabs } from "@/components/ui/Tabs";
import { fetchActivity } from "@/services/api/dashboardService";
import { ICONS } from "@/lib/icons";
import type { ThreatActivityPoint } from "@/types";

type Range = "24h" | "7d" | "30d";
const RANGE_DAYS: Record<Range, number> = { "24h": 1, "7d": 7, "30d": 30 };

const SERIES = [
  { key: "phishing", label: "Phishing", color: "#f97316" },
  { key: "impersonation", label: "Impersonation", color: "#ec4899" },
  { key: "malware", label: "Malware", color: "#ef4444" },
  { key: "suspiciousUrls", label: "Suspicious URLs", color: "#22c55e" },
  { key: "accountTakeover", label: "Account Takeover", color: "#38bdf8" },
  { key: "deepfake", label: "Deepfake", color: "#a855f7" },
  { key: "networkThreats", label: "Network Threats", color: "#eab308" },
] as const;

function ChartTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-lg border border-strong bg-elevated p-3 shadow-xl text-xs">
      <p className="font-semibold text-fg mb-1.5">{label}</p>
      {payload.map((p: any) => (
        <div key={p.dataKey} className="flex items-center justify-between gap-4 py-0.5">
          <span className="flex items-center gap-1.5 text-fg-muted">
            <span className="h-2 w-2 rounded-full" style={{ backgroundColor: p.color }} />
            {p.name}
          </span>
          <span className="font-mono text-fg">{p.value}</span>
        </div>
      ))}
    </div>
  );
}

export function ThreatActivityChart() {
  const [range, setRange] = useState<Range>("7d");
  const [data, setData] = useState<ThreatActivityPoint[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    fetchActivity(RANGE_DAYS[range])
      .then((d) => !cancelled && setData(d))
      .catch(() => !cancelled && setData([]))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [range]);

  return (
    <Card>
      <CardHeader
        title="Threat Activity"
        subtitle="Detections across all modules over time"
        icon={<ICONS.trendUp size={16} />}
        action={
          <Tabs
            size="sm"
            value={range}
            onChange={setRange}
            options={[
              { value: "24h", label: "24 Hours" },
              { value: "7d", label: "7 Days" },
              { value: "30d", label: "30 Days" },
            ]}
          />
        }
      />
      <CardBody>
        {loading && data.length === 0 ? (
          <div className="h-72 flex items-center justify-center text-sm text-fg-muted">Loading…</div>
        ) : (
        <div className="h-72">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
              <defs>
                {SERIES.map((s) => (
                  <linearGradient key={s.key} id={`grad-${s.key}`} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={s.color} stopOpacity={0.35} />
                    <stop offset="95%" stopColor={s.color} stopOpacity={0} />
                  </linearGradient>
                ))}
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" vertical={false} />
              <XAxis dataKey="label" stroke="var(--color-fg-muted)" fontSize={11} tickLine={false} axisLine={false} />
              <YAxis stroke="var(--color-fg-muted)" fontSize={11} tickLine={false} axisLine={false} />
              <Tooltip content={<ChartTooltip />} />
              <Legend wrapperStyle={{ fontSize: 11, color: "var(--color-fg-muted)" }} iconType="circle" iconSize={8} />
              {SERIES.map((s) => (
                <Area
                  key={s.key}
                  type="monotone"
                  dataKey={s.key}
                  name={s.label}
                  stroke={s.color}
                  fill={`url(#grad-${s.key})`}
                  strokeWidth={2}
                />
              ))}
            </AreaChart>
          </ResponsiveContainer>
        </div>
        )}
      </CardBody>
    </Card>
  );
}
