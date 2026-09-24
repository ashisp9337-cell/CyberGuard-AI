import { ICONS } from "@/lib/icons";
import { Reveal, SectionHeading } from "@/components/home/Reveal";

const FEATURES = [
  { icon: ICONS.brain, title: "AI-Assisted Analysis", desc: "Intelligent analysis designed to identify suspicious patterns and emerging threat indicators." },
  { icon: ICONS.eye, title: "Explainable Detection", desc: "Understand why an item was flagged with clear indicators and risk explanations." },
  { icon: ICONS.layers, title: "Multi-Layer Security", desc: "Combine file, URL, communication, multimedia, behavioral, and network analysis." },
  { icon: ICONS.dashboard, title: "Unified Visibility", desc: "View threats, scans, alerts, and security activity from a centralized dashboard." },
  { icon: ICONS.workflow, title: "Scalable Architecture", desc: "Designed for future integration with machine learning models, threat intelligence services, and security APIs." },
  { icon: ICONS.zap, title: "Actionable Intelligence", desc: "Move beyond detection with clear risk levels and recommended next steps." },
];

export function WhyCyberGuard() {
  return (
    <section id="about" className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20 sm:py-24">
      <SectionHeading center title="Security Intelligence That Goes Beyond Detection." />
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {FEATURES.map((f, i) => (
          <Reveal key={f.title} delay={i * 0.05}>
            <div className="h-full rounded-xl border border-default bg-surface p-5 hover:border-strong transition-colors">
              <div className="h-10 w-10 rounded-lg bg-cyan-500/10 flex items-center justify-center mb-3.5">
                <f.icon size={19} className="text-cyan-400" />
              </div>
              <h3 className="text-sm font-bold text-white mb-1.5">{f.title}</h3>
              <p className="text-xs text-slate-500 leading-relaxed">{f.desc}</p>
            </div>
          </Reveal>
        ))}
      </div>
    </section>
  );
}
