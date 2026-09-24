import type { HTMLAttributes, ReactNode } from "react";
import { cn } from "@/lib/utils";

export function Card({ children, className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn("rounded-xl border border-default bg-surface", className)}
      {...props}
    >
      {children}
    </div>
  );
}

export function CardHeader({ title, subtitle, action, icon }: { title: string; subtitle?: string; action?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-3 p-4 pb-3 border-b border-default">
      <div className="flex items-start gap-2.5 min-w-0">
        {icon && <div className="mt-0.5 shrink-0 text-fg-muted">{icon}</div>}
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-white truncate">{title}</h3>
          {subtitle && <p className="text-xs text-slate-500 mt-0.5">{subtitle}</p>}
        </div>
      </div>
      {action && <div className="shrink-0">{action}</div>}
    </div>
  );
}

export function CardBody({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn("p-4", className)}>{children}</div>;
}
