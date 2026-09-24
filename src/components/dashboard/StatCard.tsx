import type { ReactNode } from "react";
import { Card } from "@/components/ui/Card";
import { cn } from "@/lib/utils";
import { ICONS } from "@/lib/icons";

export function StatCard({
  label,
  value,
  icon,
  accent = "var(--color-brand)",
  delta,
  deltaLabel,
  children,
}: {
  label: string;
  value: string | number;
  icon: ReactNode;
  accent?: string;
  delta?: number;
  deltaLabel?: string;
  children?: ReactNode;
}) {
  const positive = (delta ?? 0) >= 0;
  return (
    <Card className="p-4 flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <p className="text-xs font-medium text-fg-muted">{label}</p>
        <div className="h-8 w-8 rounded-lg flex items-center justify-center" style={{ backgroundColor: `${accent}1f`, color: accent }}>
          {icon}
        </div>
      </div>
      <div className="flex items-end justify-between">
        <p className="text-2xl font-extrabold text-fg tracking-tight">{value}</p>
        {delta !== undefined && (
          <span className={cn("flex items-center gap-0.5 text-xs font-medium", positive ? "text-emerald-400" : "text-red-400")}>
            {positive ? <ICONS.trendUp size={12} /> : <ICONS.trendDown size={12} />}
            {Math.abs(delta)}% {deltaLabel}
          </span>
        )}
      </div>
      {children}
    </Card>
  );
}
