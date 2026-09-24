import { useNavigate } from "react-router-dom";
import { ICONS } from "@/lib/icons";
import { Button } from "@/components/ui/Button";
import type { DetectionModule, SubtopicConfig } from "@/types";

export function SubtopicCard({ module: mod, subtopic }: { module: DetectionModule; subtopic: SubtopicConfig }) {
  const navigate = useNavigate();
  const Icon = ICONS[subtopic.icon as keyof typeof ICONS] ?? ICONS.shieldCheck;
  return (
    <div className="rounded-xl border border-default bg-surface p-5 flex flex-col hover:border-strong transition-colors">
      <div className="h-10 w-10 rounded-lg flex items-center justify-center mb-3" style={{ backgroundColor: `${mod.color}1f`, color: mod.color }}>
        <Icon size={19} />
      </div>
      <h3 className="text-sm font-bold text-fg leading-snug">{subtopic.title}</h3>
      <p className="text-xs text-fg-muted mt-1.5 leading-relaxed flex-1">{subtopic.description}</p>
      <p className="text-[11px] text-fg-faint mt-3 flex items-center gap-1.5">
        <ICONS.upload size={12} /> {subtopic.supportedInput}
      </p>
      <Button size="sm" className="mt-4 w-full" onClick={() => navigate(`/modules/${mod.id}/${subtopic.id}`)}>
        Analyze <ICONS.chevronRight size={14} />
      </Button>
    </div>
  );
}
