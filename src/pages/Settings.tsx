import { useEffect, useState } from "react";
import { PageHeader } from "@/components/layout/PageHeader";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { TextInput } from "@/components/ui/Input";
import { useToast } from "@/context/ToastContext";
import { getSettings, updateSettings } from "@/services/api/settingsService";
import { listContacts, createContact, deleteContact, type KnownContact } from "@/services/api/contactsService";
import { ICONS } from "@/lib/icons";
import { AlertChannelsCard } from "@/components/settings/AlertChannelsCard";

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

  const [contacts, setContacts] = useState<KnownContact[]>([]);
  const [contactsLoading, setContactsLoading] = useState(true);
  const [newContactName, setNewContactName] = useState("");
  const [newContactDomain, setNewContactDomain] = useState("");
  const [newContactEmail, setNewContactEmail] = useState("");
  const [addingContact, setAddingContact] = useState(false);

  function refreshContacts() {
    setContactsLoading(true);
    listContacts()
      .then(setContacts)
      .catch(() => {})
      .finally(() => setContactsLoading(false));
  }

  useEffect(() => {
    refreshContacts();
  }, []);

  async function handleAddContact() {
    if (!newContactName.trim()) return;
    setAddingContact(true);
    try {
      await createContact({
        displayName: newContactName.trim(),
        authorizedDomain: newContactDomain.trim(),
        authorizedEmail: newContactEmail.trim(),
      });
      setNewContactName("");
      setNewContactDomain("");
      setNewContactEmail("");
      refreshContacts();
      notify({ variant: "success", title: "Contact added" });
    } catch (err) {
      notify({ variant: "critical", title: "Could not add contact", description: err instanceof Error ? err.message : "Please try again." });
    } finally {
      setAddingContact(false);
    }
  }

  async function handleDeleteContact(id: string) {
    try {
      await deleteContact(id);
      setContacts((prev) => prev.filter((c) => c.id !== id));
    } catch (err) {
      notify({ variant: "critical", title: "Could not remove contact", description: err instanceof Error ? err.message : "Please try again." });
    }
  }

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
            <Toggle checked={dashboardNotifs} onChange={setDashboardNotifs} label="Email Notifications" hint="Also send alerts by email (when email is set up below)" />
          </CardBody>
        </Card>

        <AlertChannelsCard />

        <Card className="lg:col-span-2">
          <CardHeader title="Integration Settings" subtitle="Connect external tools and threat intelligence feeds" icon={<ICONS.server size={16} />} />
          <CardBody className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <TextInput label="API Key" placeholder="sk-••••••••••••••••" type="password" hint="Never persisted server-side — configure provider API keys via backend/.env instead" disabled />
            <TextInput label="SIEM Integration Endpoint" placeholder="https://siem.yourcompany.com/ingest" value={siemEndpoint} onChange={(e) => setSiemEndpoint(e.target.value)} />
            <TextInput label="Threat Intelligence Feed URL" placeholder="https://intel.cyberguard.ai/feed" value={threatFeedUrl} onChange={(e) => setThreatFeedUrl(e.target.value)} />
            <TextInput label="External Security Tool Webhook" placeholder="https://hooks.yourcompany.com/security" value={webhookUrl} onChange={(e) => setWebhookUrl(e.target.value)} />
          </CardBody>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader
            title="Known Contacts"
            subtitle="Used by Friend / Relative / Known Contact Impersonation checks — only you can see these"
            icon={<ICONS.contact size={16} />}
          />
          <CardBody>
            <div className="grid grid-cols-1 md:grid-cols-[1fr_1fr_1fr_auto] gap-3 items-end mb-4">
              <TextInput label="Name" placeholder="e.g. Dr. S. K. Nayak (HOD)" value={newContactName} onChange={(e) => setNewContactName(e.target.value)} />
              <TextInput label="Their real domain" placeholder="e.g. bput.ac.in" value={newContactDomain} onChange={(e) => setNewContactDomain(e.target.value)} />
              <TextInput label="Their email (optional)" placeholder="e.g. sknayak@bput.ac.in" value={newContactEmail} onChange={(e) => setNewContactEmail(e.target.value)} />
              <button
                onClick={handleAddContact}
                disabled={addingContact || !newContactName.trim()}
                className="rounded-lg bg-cyan-500 text-slate-950 font-medium px-4 py-2.5 text-sm hover:bg-cyan-400 focus-ring disabled:opacity-50 h-fit"
              >
                {addingContact ? "Adding..." : "Add Contact"}
              </button>
            </div>

            {contactsLoading ? (
              <p className="text-sm text-fg-muted py-3">Loading contacts...</p>
            ) : contacts.length === 0 ? (
              <p className="text-sm text-fg-muted py-3">
                No contacts saved yet. Add someone above — a boss, a professor, a relative — so messages
                claiming to be from them can be checked against what you actually know about them.
              </p>
            ) : (
              <div className="divide-y border-t border-default mt-1">
                {contacts.map((c) => (
                  <div key={c.id} className="flex items-center justify-between gap-3 py-2.5">
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-fg truncate">{c.displayName}</p>
                      <p className="text-xs text-fg-muted truncate">
                        {c.authorizedEmail || c.authorizedDomain || "No domain/email set"}
                      </p>
                    </div>
                    <button
                      onClick={() => handleDeleteContact(c.id)}
                      aria-label={`Remove ${c.displayName}`}
                      className="text-fg-muted hover:text-red-400 focus-ring rounded p-1.5 shrink-0"
                    >
                      <ICONS.trash size={15} />
                    </button>
                  </div>
                ))}
              </div>
            )}
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
