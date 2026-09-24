import { useEffect, useState } from "react";
import { PageHeader } from "@/components/layout/PageHeader";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { TextInput } from "@/components/ui/Input";
import { useToast } from "@/context/ToastContext";
import { getSettings, updateSettings } from "@/services/api/settingsService";
import { ICONS } from "@/lib/icons";

function Toggle({ checked, onChange, label, hint }: { checked: boolean; onChange: (v: boolean) => void; label: string; hint?: string }) {
  return (
    <div className="flex items-center justify-between py-3 border-b border-default last:border-0">
      <div>
        <p className="text-sm text-white font-medium">{label}</p>
        {hint && <p className="text-xs text-slate-500 mt-0.5">{hint}</p>}
      </div>
      <button
        role="switch"
        aria-checked={checked}
        aria-label={label}
        onClick={() => onChange(!checked)}
        className={`relative h-6 w-11 rounded-full transition-colors focus-ring shrink-0 ${checked ? "bg-cyan-500" : "bg-elevated border border-strong"}`}
      >
        <span className={`absolute top-0.5 h-5 w-5 rounded-full bg-white transition-transform ${checked ? "translate-x-5" : "translate-x-0.5"}`} />
      </button>
    </div>
  );
}

export default function Settings() {
  const { notify } = useToast();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  const [autoScan, setAutoScan] = useState(true);
  const [realtimeMonitoring, setRealtimeMonitoring] = useState(true);
  const [sensitivity, setSensitivity] = useState("balanced");
  const [criticalAlerts, setCriticalAlerts] = useState(true);
  const [warningAlerts, setWarningAlerts] = useState(true);
  const [dashboardNotifs, setDashboardNotifs] = useState(false);
  const [siemEndpoint, setSiemEndpoint] = useState("");
  const [threatFeedUrl, setThreatFeedUrl] = useState("");
  const [webhookUrl, setWebhookUrl] = useState("");

  useEffect(() => {
    getSettings()
      .then((s) => {
        setSensitivity(s.sensitivity);
        setCriticalAlerts(s.notificationsEnabled);
        setDashboardNotifs(s.emailNotifications);
        const integ = s.integrationSettings ?? {};
        if (typeof integ.autoScan === "boolean") setAutoScan(integ.autoScan);
        if (typeof integ.realtimeMonitoring === "boolean") setRealtimeMonitoring(integ.realtimeMonitoring);
        if (typeof integ.warningAlerts === "boolean") setWarningAlerts(integ.warningAlerts);
        if (typeof integ.siemEndpoint === "string") setSiemEndpoint(integ.siemEndpoint);
        if (typeof integ.threatFeedUrl === "string") setThreatFeedUrl(integ.threatFeedUrl);
        if (typeof integ.webhookUrl === "string") setWebhookUrl(integ.webhookUrl);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  async function save() {
    setSaving(true);
    try {
      await updateSettings({
        sensitivity,
        notificationsEnabled: criticalAlerts,
        emailNotifications: dashboardNotifs,
        integrationSettings: { autoScan, realtimeMonitoring, warningAlerts, siemEndpoint, threatFeedUrl, webhookUrl },
      });
      notify({ variant: "success", title: "Settings saved" });
    } catch (err) {
      notify({ variant: "critical", title: "Could not save settings", description: err instanceof Error ? err.message : "Please try again." });
    } finally {
      setSaving(false);
    }
  }

  return (
    <div>
      <PageHeader title="Settings" subtitle="Configure detection sensitivity, notifications, and platform integrations." />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <Card>
          <CardHeader title="Security Settings" icon={<ICONS.shieldCheck size={16} />} />
          <CardBody>
            <Toggle checked={autoScan} onChange={setAutoScan} label="Automatic Scanning" hint="Automatically scan new uploads and inbound content" />
            <Toggle checked={realtimeMonitoring} onChange={setRealtimeMonitoring} label="Real-Time Monitoring" hint="Continuously monitor network and system activity" />
            <div className="pt-4">
              <label htmlFor="sensitivity" className="block text-sm font-medium text-white mb-1.5">AI Sensitivity</label>
              <select
                id="sensitivity"
                value={sensitivity}
                onChange={(e) => setSensitivity(e.target.value)}
                className="w-full rounded-lg bg-elevated border border-strong px-3 py-2.5 text-sm text-white focus-ring"
              >
                <option value="conservative">Conservative — fewer false positives</option>
                <option value="balanced">Balanced — recommended</option>
                <option value="aggressive">Aggressive — maximum detection</option>
              </select>
            </div>
          </CardBody>
        </Card>

        <Card>
          <CardHeader title="Notification Settings" icon={<ICONS.bell size={16} />} />
          <CardBody>
            <Toggle checked={criticalAlerts} onChange={setCriticalAlerts} label="Critical Alerts" hint="Immediate notification for critical-severity threats" />
            <Toggle checked={warningAlerts} onChange={setWarningAlerts} label="Warning Alerts" hint="Notify for medium and high severity findings" />
            <Toggle checked={dashboardNotifs} onChange={setDashboardNotifs} label="Email Notifications" hint="Also send notifications by email" />
          </CardBody>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader title="Integration Settings" subtitle="Connect external tools and threat intelligence feeds" icon={<ICONS.server size={16} />} />
          <CardBody className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <TextInput label="API Key" placeholder="sk-••••••••••••••••" type="password" hint="Never persisted server-side — configure provider API keys via backend/.env instead" disabled />
            <TextInput label="SIEM Integration Endpoint" placeholder="https://siem.yourcompany.com/ingest" value={siemEndpoint} onChange={(e) => setSiemEndpoint(e.target.value)} />
            <TextInput label="Threat Intelligence Feed URL" placeholder="https://intel.cyberguard.ai/feed" value={threatFeedUrl} onChange={(e) => setThreatFeedUrl(e.target.value)} />
            <TextInput label="External Security Tool Webhook" placeholder="https://hooks.yourcompany.com/security" value={webhookUrl} onChange={(e) => setWebhookUrl(e.target.value)} />
          </CardBody>
        </Card>
      </div>

      <div className="mt-5 flex justify-end">
        <button onClick={save} disabled={loading || saving} className="rounded-lg bg-cyan-500 text-slate-950 font-medium px-5 py-2.5 text-sm hover:bg-cyan-400 focus-ring disabled:opacity-50">
          {saving ? "Saving..." : "Save Changes"}
        </button>
      </div>
    </div>
  );
}
