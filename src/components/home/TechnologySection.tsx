import { ICONS } from "@/lib/icons";
import { Reveal, SectionHeading } from "@/components/home/Reveal";

const LAYERS = [
  { icon: ICONS.brain, label: "AI & Machine Learning" },
  { icon: ICONS.radar, label: "Threat Intelligence" },
  { icon: ICONS.behavior, label: "Behavioral Analysis" },
  { icon: ICONS.malware, label: "File & Malware Analysis" },
  { icon: ICONS.network, label: "Network & Log Analysis" },
  { icon: ICONS.gauge, label: "Risk Assessment" },
  { icon: ICONS.lightbulb, label: "Explainable Security Insights" },
];

export function TechnologySection() {
  return (
    <section id="technology" className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20 sm:py-24">
      <SectionHeading badge="Architecture" title="Intelligence Behind the Defense." center />

      <Reveal>
        <div className="max-w-md mx-auto space-y-3">
          {LAYERS.map((l, i) => (
            <div key={l.label} className="flex items-center gap-4">
              <div className="rounded-xl border border-default bg-surface px-4 py-3 flex items-center gap-3 flex-1">
                <div className="h-9 w-9 rounded-lg bg-cyan-500/10 flex items-center justify-center shrink-0">
                  <l.icon size={17} className="text-cyan-400" />
                </div>
                <span className="text-sm font-semibold text-slate-200">{l.label}</span>
              </div>
              {i < LAYERS.length - 1 && <span className="sr-only">then</span>}
            </div>
          ))}
        </div>
      </Reveal>

      <Reveal delay={0.1}>
        <div className="max-w-2xl mx-auto mt-8 rounded-xl border border-default bg-elevated p-4 flex items-start gap-3">
          <ICONS.info size={16} className="text-cyan-400 shrink-0 mt-0.5" />
          <p className="text-xs text-slate-400 leading-relaxed">
            <span className="font-semibold text-slate-300">Current prototype:</span> this build uses simulated analysis
            workflows to demonstrate the full detection experience end-to-end, and is architected to support future
            backend, ML model, and threat intelligence integrations without changing the interface.
          </p>
        </div>
      </Reveal>
    </section>
  );
}
