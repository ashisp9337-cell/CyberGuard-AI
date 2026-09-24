import { useNavigate } from "react-router-dom";
import { ICONS } from "@/lib/icons";
import type { DetectionModule } from "@/types";

export function ModuleCard({ module: mod }: { module: DetectionModule }) {
  const navigate = useNavigate();
  const Icon = ICONS[mod.icon as keyof typeof ICONS] ?? ICONS.shieldCheck;
  return (
    <button
      onClick={() => navigate(`/modules/${mod.id}`)}
      className="text-left rounded-xl border border-default bg-surface p-5 hover:border-strong hover:-translate-y-0.5 transition-all duration-150 focus-ring group"
      style={{ boxShadow: "0 0 0 0 transparent" }}
    >
      <div className="h-11 w-11 rounded-lg flex items-center justify-center mb-4" style={{ backgroundColor: `${mod.color}1f`, color: mod.color }}>
        <Icon size={22} />
      </div>
      <h3 className="text-sm font-bold text-white leading-snug">{mod.name}</h3>
      <p className="text-xs text-slate-500 mt-2 leading-relaxed line-clamp-3">{mod.description}</p>
      <div className="flex items-center justify-between mt-4 pt-3 border-t border-default">
        <span className="text-[11px] text-slate-500">{mod.subtopics.length} detection types</span>
        <ICONS.chevronRight size={15} className="text-slate-600 group-hover:text-cyan-400 group-hover:translate-x-0.5 transition-all" />
      </div>
    </button>
  );
}
