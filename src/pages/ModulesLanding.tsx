import { PageHeader } from "@/components/layout/PageHeader";
import { ModuleCard } from "@/components/modules/ModuleCard";
import { DETECTION_MODULES } from "@/data/modules";

export default function ModulesLanding() {
  return (
    <div>
      <PageHeader title="Detection Modules" subtitle="Six specialized AI-powered detection engines covering the full digital threat surface." />
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4">
        {DETECTION_MODULES.map((mod) => (
          <ModuleCard key={mod.id} module={mod} />
        ))}
      </div>
    </div>
  );
}
