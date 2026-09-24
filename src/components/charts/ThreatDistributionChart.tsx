import { useEffect, useState } from "react";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from "recharts";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { fetchThreatDistribution } from "@/services/api/dashboardService";
import { ICONS } from "@/lib/icons";
import type { ThreatDistributionSlice } from "@/types";

function DistTooltip({ active, payload }: any) {
  if (!active || !payload?.length) return null;
  const p = payload[0];
  return (
    <div className="rounded-lg border border-strong bg-elevated p-2.5 shadow-xl text-xs">
      <div className="flex items-center gap-1.5">
        <span className="h-2 w-2 rounded-full" style={{ backgroundColor: p.payload.color }} />
        <span className="text-fg font-medium">{p.name}</span>
      </div>
      <p className="text-fg-muted mt-1">{p.value}% of detections</p>
    </div>
  );
}

export function ThreatDistributionChart() {
  const [data, setData] = useState<ThreatDistributionSlice[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    fetchThreatDistribution()
      .then((d) => !cancelled && setData(d))
      .catch(() => !cancelled && setData([]))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <Card>
      <CardHeader title="Threat Distribution" subtitle="By category" icon={<ICONS.threatOverview size={16} />} />
      <CardBody>
        <div className="h-64">
          {loading ? (
            <div className="h-full flex items-center justify-center text-sm text-fg-muted">Loading…</div>
          ) : data.length === 0 ? (
            <div className="h-full flex items-center justify-center text-sm text-fg-muted">No flagged detections yet.</div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={data} dataKey="value" nameKey="name" innerRadius={55} outerRadius={85} paddingAngle={3} strokeWidth={0}>
                  {data.map((d) => (
                    <Cell key={d.name} fill={d.color} />
                  ))}
                </Pie>
                <Tooltip content={<DistTooltip />} />
                <Legend
                  layout="vertical"
                  verticalAlign="middle"
                  align="right"
                  iconType="circle"
                  iconSize={8}
                  wrapperStyle={{ fontSize: 11, color: "var(--color-fg-muted)", paddingLeft: 12 }}
                />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>
      </CardBody>
    </Card>
  );
}
