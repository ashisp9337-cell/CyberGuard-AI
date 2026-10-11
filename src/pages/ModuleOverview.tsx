import { Link, Navigate, useParams } from "react-router-dom";
import { PageHeader } from "@/components/layout/PageHeader";
import { SubtopicCard } from "@/components/modules/SubtopicCard";
import { getModule } from "@/data/modules";
import { ICONS } from "@/lib/icons";

export default function ModuleOverview() {
  const { moduleId } = useParams();
  const mod = getModule(moduleId ?? "");
  if (!mod) return <Navigate to="/dashboard" replace />;
  const Icon = ICONS[mod.icon as keyof typeof ICONS] ?? ICONS.shieldCheck;

  return (
    <div>
      <div className="flex items-center gap-3 mb-2">
        <div className="h-11 w-11 rounded-lg flex items-center justify-center" style={{ backgroundColor: `${mod.color}1f`, color: mod.color }}>
          <Icon size={22} />
        </div>
        <div>
          <p className="text-[11px] uppercase tracking-wider text-fg-muted">Detection Module</p>
          <h1 className="text-xl font-bold text-fg leading-tight">{mod.name}</h1>
        </div>
      </div>
      <p className="text-sm text-fg-muted max-w-2xl mb-6">{mod.description}</p>

      <Link
        to={`/modules/${mod.id}/auto`}
        className="mb-6 flex items-center gap-3 rounded-xl border border-default bg-elevated p-4 hover:border-cyan-500 transition-colors focus-ring"
      >
        <ICONS.scan size={18} className="text-cyan-400 shrink-0" />
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-fg">Auto-detect</p>
          <p className="text-xs text-fg-muted">Not sure which type it is? Paste or upload it and CYBERGUARD picks the right detection type.</p>
        </div>
        <ICONS.chevronRight size={16} className="text-fg-muted shrink-0" />
      </Link>

      <PageHeader title="Detection Types" subtitle={`Select a detection type below to open its dedicated analysis workspace.`} />
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4">
        {mod.subtopics.map((s) => (
          <SubtopicCard key={s.id} module={mod} subtopic={s} />
        ))}
      </div>
    </div>
  );
}
