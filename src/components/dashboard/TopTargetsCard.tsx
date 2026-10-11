import { useEffect, useState } from "react";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { Tabs } from "@/components/ui/Tabs";
import { fetchTopTargets, type TopTarget, type TopTargets } from "@/services/api/dashboardService";
import { CLASSIFICATION_META, classifyRisk } from "@/lib/severity";
import { ICONS } from "@/lib/icons";

type View = "services" | "accounts";

function Row({ item, max }: { item: TopTarget; max: number }) {
  const meta = CLASSIFICATION_META[classifyRisk(item.maxRisk)];
  const width = Math.max(6, Math.round((item.count / max) * 100));
  return (
    <li className="py-2">
      <div className="flex items-center justify-between gap-3 text-sm">
        <span className="truncate text-fg font-medium" title={item.name}>{item.name}</span>
        <span className="shrink-0 font-mono text-xs text-fg-muted">
          {item.count} {item.count === 1 ? "attack" : "attacks"}
        </span>
      </div>
      <div className="mt-1.5 h-1.5 w-full rounded-full bg-elevated overflow-hidden">
        <div className="h-full rounded-full" style={{ width: `${width}%`, backgroundColor: meta.color }} />
      </div>
      <div className="mt-1 flex flex-wrap gap-x-3 text-[10px] text-fg-muted">
        <span style={{ color: meta.color }}>Highest: {meta.label} ({item.maxRisk})</span>
        {item.category && <span className="capitalize">{item.category}</span>}
        {item.modules && item.modules.length > 0 && <span>{item.modules.join(", ")}</span>}
      </div>
    </li>
  );
}

export function TopTargetsCard({ limit = 6 }: { limit?: number }) {
  const [view, setView] = useState<View>("services");
  const [data, setData] = useState<TopTargets | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    fetchTopTargets(30, limit)
      .then((d) => !cancelled && setData(d))
      .catch(() => !cancelled && setData(null))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [limit]);

  const rows = data ? data[view] : [];
  const max = Math.max(1, ...rows.map((r) => r.count));

  return (
    <Card>
      <CardHeader
        title="Most Targeted"
        subtitle="Last 30 days, threat scans only"
        icon={<ICONS.fingerprint size={16} />}
        action={
          <Tabs
            size="sm"
            value={view}
            onChange={setView}
            options={[
              { value: "services", label: "Services" },
              { value: "accounts", label: "Accounts" },
            ]}
          />
        }
      />
      <CardBody>
        {loading ? (
          <div className="h-40 flex items-center justify-center text-sm text-fg-muted">Loading…</div>
        ) : rows.length === 0 ? (
          <div className="h-40 flex items-center justify-center text-center text-sm text-fg-muted px-4">
            {view === "services"
              ? "No impersonated organisations or brands found in flagged scans yet."
              : "No attacked accounts found yet. Email recipients and usernames in login logs appear here."}
          </div>
        ) : (
          <ul className="divide-y divide-[var(--color-border)]">
            {rows.map((item) => (
              <Row key={item.name} item={item} max={max} />
            ))}
          </ul>
        )}
      </CardBody>
    </Card>
  );
}