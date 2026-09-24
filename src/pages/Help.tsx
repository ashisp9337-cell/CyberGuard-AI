import { PageHeader } from "@/components/layout/PageHeader";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { DETECTION_MODULES } from "@/data/modules";
import { ICONS } from "@/lib/icons";

const FAQS = [
  { q: "How does CYBERGUARD AI analyze content?", a: "Each detection module runs a multi-stage AI pipeline: feature extraction, threat-intelligence lookups, static and behavioral analysis, and a final AI risk evaluation that produces a 0-100 risk score." },
  { q: "Is my uploaded data stored?", a: "In this prototype, all analysis runs against simulated mock data in your browser. No files are uploaded to a server." },
  { q: "How is the risk score calculated?", a: "Detected indicators are weighted and combined into a single risk score, which maps to a classification: Safe, Low Risk, Suspicious, High Risk, or Critical." },
  { q: "Can I connect a real backend later?", a: "Yes — the frontend's service layer is designed to swap mock data generators for real API calls without changing any UI components." },
];

export default function Help() {
  return (
    <div>
      <PageHeader title="Help & Documentation" subtitle="Learn how CYBERGUARD AI's detection modules and analysis workflow work." />
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <Card className="lg:col-span-2">
          <CardHeader title="Frequently Asked Questions" icon={<ICONS.help size={16} />} />
          <CardBody className="space-y-4">
            {FAQS.map((f) => (
              <div key={f.q}>
                <p className="text-sm font-semibold text-white">{f.q}</p>
                <p className="text-sm text-slate-400 mt-1 leading-relaxed">{f.a}</p>
              </div>
            ))}
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Detection Modules" icon={<ICONS.shieldCheck size={16} />} />
          <CardBody className="space-y-2">
            {DETECTION_MODULES.map((m) => {
              const Icon = ICONS[m.icon as keyof typeof ICONS] ?? ICONS.shieldCheck;
              return (
                <div key={m.id} className="flex items-center gap-2.5 text-sm text-slate-300">
                  <Icon size={15} style={{ color: m.color }} />
                  {m.shortName}
                </div>
              );
            })}
          </CardBody>
        </Card>
      </div>
    </div>
  );
}
