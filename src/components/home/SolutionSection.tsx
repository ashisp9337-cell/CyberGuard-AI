import { ICONS } from "@/lib/icons";
import { Reveal, SectionHeading } from "@/components/home/Reveal";

const SOURCES = ["Files", "Applications", "URLs", "Websites", "Emails", "Messages", "Images", "Videos", "Audio", "System Logs", "Network Activity"];

const LAYERS = [
  { icon: ICONS.brain, label: "AI / ML Analysis" },
  { icon: ICONS.radar, label: "Threat Intelligence" },
  { icon: ICONS.behavior, label: "Behavioral Analysis" },
  { icon: ICONS.gauge, label: "Risk Assessment" },
];

export function SolutionSection() {
  return (
    <section id="solution" className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20 sm:py-24">
      <SectionHeading
        badge="The CyberGuard Approach"
        title="One Intelligent Platform. Multiple Layers of Defense."
        subtitle="CyberGuard provides a unified security intelligence layer for analyzing different categories of modern cyber threats. Instead of relying on a single detection method, the platform is designed around a multi-layered approach."
      />

      <Reveal>
        <div className="rounded-2xl border border-default bg-surface p-6 sm:p-10">
          {/* data sources */}
          <p className="text-center text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-3">Data Sources</p>
          <div className="flex flex-wrap justify-center gap-2 mb-6">
            {SOURCES.map((s) => (
              <span key={s} className="rounded-full border border-default bg-elevated px-3 py-1 text-xs text-slate-400">{s}</span>
            ))}
          </div>

          <div className="flex justify-center mb-6">
            <ICONS.arrowRight size={18} className="text-slate-600 rotate-90" />
          </div>

          {/* intelligence layer */}
          <div className="flex justify-center mb-6">
            <div className="rounded-xl border border-cyan-500/30 bg-cyan-500/10 px-6 py-4 text-center max-w-md">
              <p className="text-sm font-bold text-cyan-300 tracking-wide">CYBERGUARD INTELLIGENCE LAYER</p>
              <p className="text-xs text-slate-400 mt-1">Unified processing across every detection module</p>
            </div>
          </div>

          <div className="flex justify-center mb-6">
            <ICONS.arrowRight size={18} className="text-slate-600 rotate-90" />
          </div>

          {/* analysis layers */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-6">
            {LAYERS.map((l) => (
              <div key={l.label} className="rounded-lg border border-default bg-elevated px-3 py-4 text-center">
                <l.icon size={18} className="text-cyan-400 mx-auto mb-2" />
                <p className="text-xs font-semibold text-slate-300">{l.label}</p>
              </div>
            ))}
          </div>

          <div className="flex justify-center mb-6">
            <ICONS.arrowRight size={18} className="text-slate-600 rotate-90" />
          </div>

          {/* output */}
          <div className="flex justify-center">
            <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-6 py-3 text-center">
              <p className="text-sm font-bold text-emerald-300 tracking-wide">SECURITY INSIGHTS &amp; RESPONSE</p>
            </div>
          </div>
        </div>
      </Reveal>
    </section>
  );
}
