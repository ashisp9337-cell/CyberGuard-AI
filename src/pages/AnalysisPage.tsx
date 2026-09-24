import { Navigate, useParams, Link } from "react-router-dom";
import { getModule, getSubtopic } from "@/data/modules";
import { ICONS } from "@/lib/icons";
import { AnalysisWorkspace } from "@/components/analysis/AnalysisWorkspace";

export default function AnalysisPage() {
  const { moduleId, subtopicId } = useParams();
  const mod = getModule(moduleId ?? "");
  const subtopic = getSubtopic(moduleId ?? "", subtopicId ?? "");
  if (!mod || !subtopic) return <Navigate to="/dashboard" replace />;

  return (
    <div className="max-w-3xl mx-auto">
      <nav aria-label="Breadcrumb" className="flex items-center gap-1.5 text-xs text-slate-500 mb-4">
        <Link to="/dashboard" className="hover:text-slate-300 focus-ring rounded">Dashboard</Link>
        <ICONS.chevronRight size={12} />
        <Link to={`/modules/${mod.id}`} className="hover:text-slate-300 focus-ring rounded">{mod.shortName}</Link>
        <ICONS.chevronRight size={12} />
        <span className="text-slate-300">{subtopic.title}</span>
      </nav>

      <AnalysisWorkspace module={mod} subtopic={subtopic} />
    </div>
  );
}
