import type { ReactNode } from "react";

export function AuthCard({ title, subtitle, children, footer }: { title: string; subtitle: string; children: ReactNode; footer?: ReactNode }) {
  return (
    <div>
      <h1 className="text-2xl font-bold text-white tracking-tight">{title}</h1>
      <p className="text-sm text-slate-400 mt-2 mb-7">{subtitle}</p>
      {children}
      {footer && <div className="mt-6">{footer}</div>}
    </div>
  );
}
