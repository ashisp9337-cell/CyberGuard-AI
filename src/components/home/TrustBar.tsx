import { ICONS } from "@/lib/icons";
import { Reveal } from "@/components/home/Reveal";

const ITEMS = [
  { icon: ICONS.cpu, label: "AI-Assisted Analysis" },
  { icon: ICONS.layers, label: "Multi-Layer Detection" },
  { icon: ICONS.eye, label: "Explainable Security Insights" },
  { icon: ICONS.dashboard, label: "Unified Threat Visibility" },
];

export function TrustBar() {
  return (
    <section className="border-y border-default bg-surface/60">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        <Reveal>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            {ITEMS.map((item) => (
              <div key={item.label} className="flex items-center gap-2.5 justify-center lg:justify-start">
                <item.icon size={16} className="text-cyan-400 shrink-0" />
                <span className="text-xs sm:text-sm font-semibold text-slate-300 tracking-wide uppercase">{item.label}</span>
              </div>
            ))}
          </div>
        </Reveal>
      </div>
    </section>
  );
}
