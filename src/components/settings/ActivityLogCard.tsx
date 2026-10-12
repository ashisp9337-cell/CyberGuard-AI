import { useEffect, useState } from "react";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { ICONS } from "@/lib/icons";
import { listAudit, type AuditEntry } from "@/services/api/auditService";

function when(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleString(undefined, { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
}

function browser(ua: string): string {
  if (!ua) return "";
  if (/edg\//i.test(ua)) return "Edge";
  if (/chrome\//i.test(ua)) return "Chrome";
  if (/firefox\//i.test(ua)) return "Firefox";
  if (/safari\//i.test(ua)) return "Safari";
  return "Other";
}

export function ActivityLogCard() {
  const [rows, setRows] = useState<AuditEntry[] | null>(null);

  useEffect(() => {
    listAudit(50).then(setRows).catch(() => setRows([]));
  }, []);

  return (
    <Card className="lg:col-span-2">
      <CardHeader
        title="Activity Log"
        subtitle="Security record of your account: sign-ins, failed sign-ins, settings and incident actions (passwords and codes are never stored)"
        icon={<ICONS.logs size={16} />}
      />
      <CardBody>
        {rows === null ? (
          <p className="text-xs text-slate-500">Loading…</p>
        ) : rows.length === 0 ? (
          <p className="text-xs text-slate-500">No activity recorded yet.</p>
        ) : (
          <ul className="divide-y divide-[var(--color-border-default,rgba(255,255,255,0.06))] max-h-80 overflow-y-auto pr-1">
            {rows.map((r) => (
              <li key={r.id} className="py-2 flex items-start justify-between gap-3 text-xs">
                <div className="min-w-0">
                  <p className={`font-medium ${r.success ? "text-white" : "text-red-400"}`}>
                    {r.success ? "" : "✕ "}
                    {r.label}
                    {r.target && <span className="text-slate-400 font-normal"> · {r.target}</span>}
                  </p>
                  <p className="text-slate-500 truncate">
                    {r.actor}
                    {r.ip && <> · IP {r.ip}</>}
                    {browser(r.userAgent) && <> · {browser(r.userAgent)}</>}
                  </p>
                </div>
                <span className="text-slate-500 shrink-0">{when(r.at)}</span>
              </li>
            ))}
          </ul>
        )}
      </CardBody>
    </Card>
  );
}
