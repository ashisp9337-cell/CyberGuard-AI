import { cn } from "@/lib/utils";

export function ProgressBar({ value, className, color }: { value: number; className?: string; color?: string }) {
  return (
    <div className={cn("h-2 w-full rounded-full bg-elevated overflow-hidden", className)} role="progressbar" aria-valuenow={value} aria-valuemin={0} aria-valuemax={100}>
      <div
        className="h-full rounded-full transition-all duration-500 ease-out"
        style={{ width: `${Math.min(100, Math.max(0, value))}%`, backgroundColor: color ?? "var(--color-brand)" }}
      />
    </div>
  );
}

export function CircularScore({ value, size = 128, strokeWidth = 10, label, color }: { value: number; size?: number; strokeWidth?: number; label?: string; color?: string }) {
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (value / 100) * circumference;
  const resolvedColor = color ?? (value >= 85 ? "var(--color-safe)" : value >= 60 ? "var(--color-warning)" : "var(--color-critical)");
  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={radius} stroke="var(--color-elevated)" strokeWidth={strokeWidth} fill="none" />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke={resolvedColor}
          strokeWidth={strokeWidth}
          fill="none"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 1s cubic-bezier(0.4,0,0.2,1)" }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-extrabold text-fg leading-none">{value}</span>
        {label && <span className="text-[10px] uppercase tracking-wider text-fg-muted mt-1">{label}</span>}
      </div>
    </div>
  );
}
