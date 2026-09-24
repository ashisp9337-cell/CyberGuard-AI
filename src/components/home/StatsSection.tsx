import { DETECTION_MODULES } from "@/data/modules";
import { Reveal } from "@/components/home/Reveal";

export function StatsSection() {
  const moduleCount = DETECTION_MODULES.length;
  const capabilityCount = DETECTION_MODULES.reduce((sum, m) => sum + m.subtopics.length, 0);

  const stats = [
    { value: `${moduleCount}+`, label: "Security Domains" },
    { value: `${capabilityCount}+`, label: "Threat Analysis Capabilities" },
    { value: "AI", label: "Assisted Analysis" },
    { value: "Modular", label: "Security Architecture" },
  ];

  return (
    <section className="border-y border-default bg-surface/40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
        <Reveal>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-6 text-center">
            {stats.map((s) => (
              <div key={s.label}>
                <p className="text-3xl sm:text-4xl font-extrabold text-cyan-300 tracking-tight">{s.value}</p>
                <p className="text-xs sm:text-sm text-slate-500 mt-1.5 uppercase tracking-wide">{s.label}</p>
              </div>
            ))}
          </div>
        </Reveal>
      </div>
    </section>
  );
}
