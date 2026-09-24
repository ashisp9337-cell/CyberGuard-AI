import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { Button } from "@/components/ui/Button";
import { CircularScore } from "@/components/ui/Progress";
import { SeverityBadge } from "@/components/ui/Badge";
import { ICONS } from "@/lib/icons";
import { Reveal, SectionHeading } from "@/components/home/Reveal";

function FloatingCard({ className, delay, children }: { className: string; delay: number; children: React.ReactNode }) {
  return (
    <motion.div
      className={`absolute rounded-xl border border-strong bg-elevated shadow-2xl p-3.5 ${className}`}
      animate={{ y: [0, -8, 0] }}
      transition={{ duration: 4, repeat: Infinity, ease: "easeInOut", delay }}
    >
      {children}
    </motion.div>
  );
}

export function DashboardPreview() {
  const navigate = useNavigate();

  return (
    <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20 sm:py-24">
      <SectionHeading
        title="Built for Modern Digital Threats."
        subtitle="A unified workspace for monitoring suspicious activity, investigating threats, analyzing digital content, and understanding security risks."
      />

      <Reveal>
        <div className="relative rounded-2xl border border-default bg-surface p-6 sm:p-10 overflow-hidden">
          <div
            className="absolute inset-0 pointer-events-none"
            style={{ background: "radial-gradient(ellipse 50% 40% at 50% 0%, rgba(34,211,238,0.06), transparent 70%)" }}
            aria-hidden="true"
          />

          <div className="relative grid lg:grid-cols-[auto_1fr] gap-8 items-center">
            <div className="flex justify-center">
              <CircularScore value={92} size={150} strokeWidth={12} label="SECURITY SCORE" color="var(--color-safe)" />
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              {[
                { label: "Active Threats", value: "24", color: "var(--color-critical)" },
                { label: "Scanned Items", value: "12.4K", color: "var(--color-brand)" },
                { label: "Suspicious", value: "37", color: "var(--color-warning)" },
                { label: "Reports", value: "164", color: "var(--color-info)" },
              ].map((s) => (
                <div key={s.label} className="rounded-lg border border-default bg-elevated p-3">
                  <p className="text-[10px] uppercase tracking-wide text-slate-500 mb-1">{s.label}</p>
                  <p className="text-lg font-extrabold" style={{ color: s.color }}>{s.value}</p>
                </div>
              ))}
              <p className="col-span-2 sm:col-span-4 text-[11px] text-slate-500 flex items-center gap-1.5 mt-1">
                <ICONS.info size={12} /> Illustrative interface example, not live production data.
              </p>
            </div>
          </div>

          {/* floating status cards, hidden on small screens to avoid overlap */}
          <FloatingCard className="hidden lg:block top-8 right-10 w-52" delay={0}>
            <div className="flex items-center justify-between mb-1.5">
              <SeverityBadge severity="critical" size="sm" />
            </div>
            <p className="text-xs font-semibold text-white">Critical Threat</p>
            <p className="text-[11px] text-slate-500 mt-0.5">Risk Score: 92</p>
          </FloatingCard>

          <FloatingCard className="hidden lg:block bottom-10 right-24 w-52" delay={1.2}>
            <div className="flex items-center justify-between mb-1.5">
              <SeverityBadge severity="high" size="sm" />
            </div>
            <p className="text-xs font-semibold text-white">Suspicious URL</p>
            <p className="text-[11px] text-slate-500 mt-0.5">Risk Score: 76</p>
          </FloatingCard>

          <FloatingCard className="hidden xl:block top-1/2 -translate-y-1/2 -right-2 w-48" delay={2}>
            <div className="flex items-center gap-1.5 mb-1">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 pulse-live" />
              <span className="text-[10px] font-semibold uppercase text-emerald-400">Security Status</span>
            </div>
            <p className="text-xs font-semibold text-white">Monitoring Ready</p>
          </FloatingCard>
        </div>
      </Reveal>

      <div className="flex justify-center mt-8">
        <Button size="lg" onClick={() => navigate("/dashboard")}>
          View Security Dashboard <ICONS.arrowRight size={16} />
        </Button>
      </div>
    </section>
  );
}
