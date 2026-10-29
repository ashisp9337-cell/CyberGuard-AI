// Windows event-log incidents (Security / Sysmon / PowerShell / Defender), attributed to user and computer.
// Backend: app/detectors/windows_events.py - rules written from MITRE ATT&CK, tested on OTRF attack recordings.
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { SeverityBadge } from "@/components/ui/Badge";
import { ICONS } from "@/lib/icons";
import type { Severity, WindowsEventsInfo } from "@/types";

export function WindowsEventsCard({ we }: { we: WindowsEventsInfo }) {
  const main = we.incidents.filter((i) => i.severity !== "low");
  const notes = we.incidents.filter((i) => i.severity === "low");
  return (
    <Card>
      <CardHeader title="Windows Event Log Findings"
                  subtitle={`${we.events.toLocaleString()} events · ${we.hosts} computer(s) · ${we.users} user(s)${we.timeRange ? ` · ${we.timeRange[0]} – ${we.timeRange[1]}` : ""}`}
                  icon={<ICONS.logs size={16} />} />
      <CardBody className="space-y-2">
        {main.length === 0 && (
          <p className="text-sm text-slate-500 py-2 text-center">No attack or misuse pattern found in these events.</p>
        )}
        {main.map((i) => (
          <div key={`${i.rule}-${i.user}-${i.host}-${i.label}`} className="rounded-lg border border-default bg-elevated p-3">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={i.severity as Severity} size="sm" />
              <span className="text-sm font-medium text-white">{i.label}</span>
              <span className="text-[11px] rounded px-1.5 py-0.5 bg-white/5 text-slate-400">{i.lens}</span>
              <span className="ml-auto text-[11px] text-slate-500 mono">{i.mitre}</span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              <span className="mono text-slate-300">{i.user}</span> on <span className="mono text-slate-300">{i.host}</span>
              {" · "}{i.count}×{i.first ? ` · from ${i.first}` : ""}{i.last && i.last !== i.first ? ` to ${i.last}` : ""}
            </p>
            {i.examples.length > 0 && (
              <ul className="mt-1 space-y-0.5">
                {i.examples.map((e) => <li key={e} className="text-[11px] text-slate-500 mono break-all">{e}</li>)}
              </ul>
            )}
          </div>
        ))}
        {notes.length > 0 && (
          <details className="text-xs text-slate-500">
            <summary className="cursor-pointer">{notes.length} low-priority note(s) (usually normal Windows activity)</summary>
            <ul className="mt-1 space-y-0.5">
              {notes.map((i) => (
                <li key={`${i.rule}-${i.user}-${i.host}-${i.label}`}>• {i.label} — {i.user} on {i.host} ({i.count}×)</li>
              ))}
            </ul>
          </details>
        )}
        <p className="text-[11px] text-slate-500">
          Rules written from MITRE ATT&CK and tested on real attack recordings (OTRF Security-Datasets). Each finding names
          who did it and where; check it with the person or team before acting.
          {we.activityDays >= 7 ? " Logons from this log were also compared with each person's normal working times (Insider Risk)." : ""}
        </p>
      </CardBody>
    </Card>
  );
}
