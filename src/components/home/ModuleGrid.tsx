import { useNavigate } from "react-router-dom";
import { DETECTION_MODULES } from "@/data/modules";
import { ICONS } from "@/lib/icons";
import { Button } from "@/components/ui/Button";
import { Reveal, SectionHeading } from "@/components/home/Reveal";

export function ModuleGrid() {
  const navigate = useNavigate();

  return (
    <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20 sm:py-24">
      <SectionHeading
        title="Comprehensive Protection Across the Digital Attack Surface."
        subtitle="CyberGuard brings multiple cybersecurity detection capabilities into one unified platform."
      />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {DETECTION_MODULES.map((mod, i) => {
          const Icon = ICONS[mod.icon as keyof typeof ICONS] ?? ICONS.shieldCheck;
          const preview = mod.subtopics.slice(0, 4);
          return (
            <Reveal key={mod.id} delay={i * 0.05}>
              <div className="h-full rounded-xl border border-default bg-surface p-6 flex flex-col">
                <div className="flex items-start gap-3 mb-4">
                  <div
                    className="h-11 w-11 rounded-lg flex items-center justify-center shrink-0"
                    style={{ backgroundColor: `${mod.color}1f`, color: mod.color }}
                  >
                    <Icon size={22} />
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-white leading-snug">{mod.name}</h3>
                    <p className="text-xs text-slate-500 mt-1">{mod.subtopics.length} detection capabilities</p>
                  </div>
                </div>
                <p className="text-sm text-slate-400 leading-relaxed mb-4">{mod.description}</p>
                <div className="flex flex-wrap gap-1.5 mb-5">
                  {preview.map((s) => (
                    <span key={s.id} className="rounded-full border border-default bg-elevated px-2.5 py-1 text-[11px] text-slate-400">
                      {s.title}
                    </span>
                  ))}
                  {mod.subtopics.length > preview.length && (
                    <span className="rounded-full border border-default bg-elevated px-2.5 py-1 text-[11px] text-slate-500">
                      +{mod.subtopics.length - preview.length} more
                    </span>
                  )}
                </div>
                <Button variant="secondary" className="mt-auto w-full" onClick={() => navigate(`/modules/${mod.id}`)}>
                  Explore Module <ICONS.chevronRight size={14} />
                </Button>
              </div>
            </Reveal>
          );
        })}
      </div>
    </section>
  );
}
