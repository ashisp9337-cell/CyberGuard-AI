import { useNavigate } from "react-router-dom";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { ICONS } from "@/lib/icons";

const ACTIONS = [
  { label: "Scan File", icon: ICONS.malware, to: "/modules/cyber-threat/malware-detection" },
  { label: "Scan Application", icon: ICONS.malware, to: "/modules/cyber-threat/malware-detection" },
  { label: "Analyze URL", icon: ICONS.url, to: "/modules/url-security/domain-spoofing" },
  { label: "Analyze Message", icon: ICONS.message, to: "/modules/phishing/sms-analysis" },
  { label: "Analyze Email", icon: ICONS.email, to: "/modules/phishing/email-analysis" },
  { label: "Analyze QR Code", icon: ICONS.qrcode, to: "/modules/phishing/qr-phishing" },
  { label: "Check Image", icon: ICONS.image, to: "/modules/deepfake/image-analysis" },
  { label: "Check Video", icon: ICONS.video, to: "/modules/deepfake/video-analysis" },
  { label: "Analyze Audio", icon: ICONS.audio, to: "/modules/deepfake/audio-analysis" },
  { label: "Monitor Account", icon: ICONS.credential, to: "/modules/credential/failed-logins" },
  { label: "Scan Network", icon: ICONS.network, to: "/modules/cyber-threat/network-traffic" },
  { label: "Analyze Logs", icon: ICONS.logs, to: "/modules/cyber-threat/log-analysis" },
  { label: "Generate Report", icon: ICONS.reports, to: "/reports" },
];

export function QuickActions() {
  const navigate = useNavigate();
  return (
    <Card>
      <CardHeader title="Quick Actions" subtitle="Jump straight into an analysis workspace" icon={<ICONS.zap size={16} />} />
      <CardBody>
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2.5">
          {ACTIONS.map((a) => (
            <button
              key={a.label}
              onClick={() => navigate(a.to)}
              className="flex flex-col items-center gap-2 rounded-lg border border-default bg-elevated px-3 py-4 text-center hover:border-cyan-500/40 hover:bg-cyan-500/5 transition-colors focus-ring group"
            >
              <a.icon size={20} className="text-fg-muted group-hover:text-cyan-400 transition-colors" />
              <span className="text-xs font-medium text-fg-secondary group-hover:text-fg leading-tight">{a.label}</span>
            </button>
          ))}
        </div>
      </CardBody>
    </Card>
  );
}
