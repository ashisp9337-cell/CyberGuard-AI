import { ICONS } from "@/lib/icons";
import { Reveal, SectionHeading } from "@/components/home/Reveal";

const PRINCIPLES = [
  { icon: ICONS.scan, title: "Detect", desc: "Identify suspicious activity across multiple attack surfaces." },
  { icon: ICONS.cpu, title: "Analyze", desc: "Understand patterns, indicators, behavior, and potential risks." },
  { icon: ICONS.eye, title: "Explain", desc: "Show why an activity was flagged instead of producing a black-box result." },
  { icon: ICONS.send, title: "Respond", desc: "Provide clear recommendations for investigation and mitigation." },
];

export function MissionSection() {
  return (
    <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16" id="mission">
      <SectionHeading
        center
        title="Our Mission"
        subtitle={'"To transform complex cyber threat detection into clear, actionable security intelligence." Our mission is to simplify complex cybersecurity by combining artificial intelligence, threat intelligence, behavioral analysis, and explainable security insights into one unified platform.'}
      />
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {PRINCIPLES.map((p, i) => (
          <Reveal key={p.title} delay={i * 0.08} className="text-center">
            <div className="h-12 w-12 rounded-xl bg-cyan-500/10 flex items-center justify-center mx-auto mb-3">
              <p.icon size={20} className="text-cyan-400" />
            </div>
            <h3 className="text-sm font-bold text-white mb-1.5">{p.title}</h3>
            <p className="text-xs text-slate-500 leading-relaxed">{p.desc}</p>
          </Reveal>
        ))}
      </div>
    </section>
  );
}
