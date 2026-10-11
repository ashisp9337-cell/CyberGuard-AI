import { PageHeader } from "@/components/layout/PageHeader";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { DETECTION_MODULES } from "@/data/modules";
import { ICONS } from "@/lib/icons";

const FAQS = [
  { q: "How does CYBERGUARD AI analyze content?", a: "Each detection module runs a multi-stage AI pipeline: feature extraction, threat-intelligence lookups, static and behavioral analysis, and a final AI risk evaluation that produces a 0-100 risk score." },
  { q: "Is my uploaded data stored?", a: "Yes. Every scan result is stored in the CYBERGUARD database (PostgreSQL) under your account so it appears in Scan History, the dashboard and reports. Uploaded files are kept on the server under random names in a private uploads folder and are never executed." },
  { q: "How is the risk score calculated?", a: "Detected indicators are weighted and combined into a single risk score, which maps to a classification: Safe, Low Risk, Suspicious, High Risk, or Critical." },
  { q: "What happens when a serious threat is found?", a: "High-risk and critical detections open an incident on the dashboard, suggest specific response actions, quarantine dangerous emails automatically, and — if configured — alert the security team on Telegram or email. You can also press \"Escalate to Team\" on any result." },
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
