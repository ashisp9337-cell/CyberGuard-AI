import { useNavigate } from "react-router-dom";
import { DETECTION_MODULES } from "@/data/modules";
import { ICONS } from "@/lib/icons";
import { Reveal, SectionHeading } from "@/components/home/Reveal";

export function ProblemSection() {
  const navigate = useNavigate();

  return (
    <section id="platform" className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20 sm:py-24">
      <SectionHeading
        title="Cyber Threats Are Evolving. Security Must Evolve Too."
        subtitle="Modern cyber threats no longer come from a single source. Phishing attacks imitate trusted organizations. Deepfakes manipulate digital identity. Malicious software can hide inside seemingly legitimate files. Compromised accounts may behave like legitimate users. Traditional security tools often analyze threats in isolation — CyberGuard is designed to bring multiple layers of threat detection together into one intelligent security platform."
      />

      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4">
        {DETECTION_MODULES.map((mod, i) => {
          const Icon = ICONS[mod.icon as keyof typeof ICONS] ?? ICONS.shieldCheck;
          return (
            <Reveal key={mod.id} delay={i * 0.06}>
              <button
                onClick={() => navigate(`/modules/${mod.id}`)}
                className="w-full h-full text-left rounded-xl border border-default bg-surface p-5 hover:border-strong hover:-translate-y-0.5 transition-all duration-150 focus-ring group"
              >
                <div
                  className="h-11 w-11 rounded-lg flex items-center justify-center mb-4"
                  style={{ backgroundColor: `${mod.color}1f`, color: mod.color }}
                >
                  <Icon size={22} />
                </div>
                <h3 className="text-sm font-bold text-white leading-snug">{mod.name}</h3>
                <p className="text-xs text-slate-500 mt-2 leading-relaxed">{mod.description}</p>
                <span className="inline-flex items-center gap-1 text-xs font-medium text-cyan-400 mt-4 group-hover:gap-1.5 transition-all">
                  Explore module <ICONS.chevronRight size={13} />
                </span>
              </button>
            </Reveal>
          );
        })}
      </div>
    </section>
  );
}
