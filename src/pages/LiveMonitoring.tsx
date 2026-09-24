import { useEffect, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { PageHeader } from "@/components/layout/PageHeader";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { SeverityBadge, StatusPill } from "@/components/ui/Badge";
import { useAppContext } from "@/context/AppContext";
import { fetchLiveFeed } from "@/services/api/dashboardService";
import { subscribeLiveEvents } from "@/services/api/monitoringService";
import { API_CONFIG } from "@/services/api/config";
import { formatRelativeTime } from "@/lib/utils";
import { ICONS } from "@/lib/icons";
import type { LiveEvent } from "@/types";

export default function LiveMonitoring() {
  const { monitoringActive, setMonitoringActive } = useAppContext();
  const [events, setEvents] = useState<LiveEvent[]>([]);

  // Seed with recent history, then subscribe to the real SSE stream
  // (GET /api/monitoring/stream) for new events as they're created by
  // scans or POST /api/events — no client-side random generator.
  useEffect(() => {
    if (API_CONFIG.useMockData) {
      import("@/services/mock/mockData").then(({ generateLiveEvents }) => setEvents(generateLiveEvents(14)));
      return;
    }
    fetchLiveFeed(30).then(setEvents).catch(() => {});
  }, []);

  useEffect(() => {
    if (!monitoringActive || API_CONFIG.useMockData) return;
    const unsubscribe = subscribeLiveEvents((ev) => {
      setEvents((prev) => (prev.some((e) => e.id === ev.id) ? prev : [ev, ...prev].slice(0, 60)));
    });
    return unsubscribe;
  }, [monitoringActive]);

  return (
    <div>
      <PageHeader
        title="Live Monitoring"
        subtitle="Real-time visibility into scans and security events as they happen, streamed live from the backend."
        action={
          <div className="flex gap-2">
            <Button variant={monitoringActive ? "secondary" : "primary"} size="sm" onClick={() => setMonitoringActive(true)} disabled={monitoringActive}>
              <ICONS.play size={14} /> Start Monitoring
            </Button>
            <Button variant={monitoringActive ? "danger" : "secondary"} size="sm" onClick={() => setMonitoringActive(false)} disabled={!monitoringActive}>
              <ICONS.pause size={14} /> Pause
            </Button>
            <Button variant="ghost" size="sm" onClick={() => setEvents([])}>
              <ICONS.trash size={14} /> Clear Alerts
            </Button>
          </div>
        }
      />

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
        <div className="xl:col-span-3">
          <Card>
            <CardHeader
              title="Live Event Stream"
              subtitle="Backed by real scan/event activity — trigger a scan in another tab to see it appear here"
              icon={<ICONS.liveMonitoring size={16} />}
              action={
                <span className={`flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide ${monitoringActive ? "text-emerald-400" : "text-slate-500"}`}>
                  <span className={`h-1.5 w-1.5 rounded-full ${monitoringActive ? "bg-emerald-400 pulse-live" : "bg-slate-600"}`} />
                  {monitoringActive ? "Monitoring" : "Paused"}
                </span>
              }
            />
            <CardBody className="p-0">
              <ul className="divide-y divide-[var(--color-border)] max-h-[560px] overflow-y-auto">
                <AnimatePresence initial={false}>
                  {events.map((ev) => (
                    <motion.li
                      key={ev.id}
                      layout
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      exit={{ opacity: 0 }}
                      className="px-4 py-3 flex items-start gap-3"
                    >
                      <SeverityBadge severity={ev.severity} size="sm" />
                      <div className="min-w-0 flex-1">
                        <p className="text-sm text-white font-medium leading-snug">{ev.title}</p>
                        <p className="text-xs text-slate-500 mt-0.5">{ev.description}</p>
                        <p className="text-[11px] text-slate-600 mt-1 mono truncate">{ev.target}</p>
                      </div>
                      <div className="text-right shrink-0">
                        <StatusPill status={ev.status} />
                        <p className="text-[10px] text-slate-600 mt-1">{formatRelativeTime(ev.timestamp)}</p>
                      </div>
                    </motion.li>
                  ))}
                </AnimatePresence>
                {events.length === 0 && <li className="px-4 py-10 text-center text-sm text-slate-500">No alerts. Feed cleared — run a scan to see live activity.</li>}
              </ul>
            </CardBody>
          </Card>
        </div>
      </div>
    </div>
  );
}
