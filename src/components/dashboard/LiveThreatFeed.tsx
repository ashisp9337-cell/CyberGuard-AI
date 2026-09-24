import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { SeverityBadge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { fetchLiveFeed } from "@/services/api/dashboardService";
import { formatRelativeTime } from "@/lib/utils";
import { ICONS } from "@/lib/icons";
import type { LiveEvent } from "@/types";

/**
 * Polls GET /api/dashboard/live-feed, which reflects real ThreatEvent rows
 * created by scans and POST /api/events. (A push-based SSE stream is also
 * available at GET /api/monitoring/stream for a future upgrade to this
 * component — polling was chosen here to keep the change minimal.)
 */
export function LiveThreatFeed({ limit = 8, live = true }: { limit?: number; live?: boolean }) {
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    const load = () => fetchLiveFeed(limit).then((e) => mounted.current && setEvents(e)).catch(() => {}).finally(() => mounted.current && setLoading(false));
    load();
    if (!live) return;
    const interval = setInterval(load, 8000);
    return () => {
      mounted.current = false;
      clearInterval(interval);
    };
  }, [live, limit]);

  return (
    <Card>
      <CardHeader
        title="Live Threat Feed"
        subtitle="Real-time detections across the platform"
        icon={<ICONS.radar size={16} />}
        action={
          <span className="flex items-center gap-1.5 text-[11px] font-semibold text-emerald-400 uppercase tracking-wide">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 pulse-live" /> Live
          </span>
        }
      />
      <CardBody className="p-0">
        {loading ? (
          <div className="py-10 text-center text-sm text-slate-500">Loading…</div>
        ) : events.length === 0 ? (
          <div className="py-10 text-center text-sm text-slate-500">No threat events yet — run a scan or wait for activity.</div>
        ) : (
        <ul className="divide-y divide-[var(--color-border)] max-h-[460px] overflow-y-auto">
          <AnimatePresence initial={false}>
            {events.map((ev) => (
              <motion.li
                key={ev.id}
                layout
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: "auto" }}
                exit={{ opacity: 0, height: 0 }}
                transition={{ duration: 0.25 }}
              >
                <button
                  onClick={() => navigate("/scan-history")}
                  className="w-full text-left px-4 py-3 hover:bg-elevated transition-colors focus-ring flex items-start gap-3"
                >
                  <SeverityBadge severity={ev.severity} size="sm" />
                  <div className="min-w-0 flex-1">
                    <p className="text-sm text-white font-medium leading-snug">{ev.title}</p>
                    <p className="text-xs text-slate-500 truncate mt-0.5 mono">{ev.target}</p>
                  </div>
                  <div className="text-right shrink-0">
                    <p className="text-xs font-mono text-slate-400">{ev.riskScore}</p>
                    <p className="text-[10px] text-slate-600 mt-0.5">{formatRelativeTime(ev.timestamp)}</p>
                  </div>
                </button>
              </motion.li>
            ))}
          </AnimatePresence>
        </ul>
        )}
        <div className="p-3 border-t border-default">
          <Button variant="ghost" size="sm" className="w-full" onClick={() => navigate("/live-monitoring")}>
            View Live Monitoring <ICONS.chevronRight size={14} />
          </Button>
        </div>
      </CardBody>
    </Card>
  );
}
