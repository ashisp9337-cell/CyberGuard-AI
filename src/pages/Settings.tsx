import { useEffect, useState } from "react";
import { PageHeader } from "@/components/layout/PageHeader";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { TextInput } from "@/components/ui/Input";
import { useToast } from "@/context/ToastContext";
import { getSettings, updateSettings } from "@/services/api/settingsService";
import { listContacts, createContact, deleteContact, importContacts, deleteAllContacts, type KnownContact } from "@/services/api/contactsService";
import { ICONS } from "@/lib/icons";
import { AlertChannelsCard } from "@/components/settings/AlertChannelsCard";
import { AutomationCard } from "@/components/settings/AutomationCard";
import { BrowserExtensionCard } from "@/components/settings/BrowserExtensionCard";
import { FileQuarantineCard } from "@/components/settings/FileQuarantineCard";
import { ActivityLogCard } from "@/components/settings/ActivityLogCard";

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

  const [sensitivity, setSensitivity] = useState("balanced");
  const [criticalAlerts, setCriticalAlerts] = useState(true);
  const [dashboardNotifs, setDashboardNotifs] = useState(false);
  const [automaticAlerts, setAutomaticAlerts] = useState<"critical" | "same">("critical");

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

  // (11 Nov) import a phone / Google / Outlook contacts export; only names + first e-mail are kept
  const [importing, setImporting] = useState(false);
  const [showImportHelp, setShowImportHelp] = useState(false);
  const [contactFilter, setContactFilter] = useState("");

  async function handleImportContacts(file: File | undefined) {
    if (!file) return;
    setImporting(true);
    try {
      const r = await importContacts(file);
      const notes = [
        r.duplicates ? `${r.duplicates} already saved` : "",
        r.withoutName ? `${r.withoutName} without a name skipped` : "",
        r.overLimit ? `${r.overLimit} over the 5,000 limit` : "",
      ].filter(Boolean).join(" · ");
      notify({ variant: r.imported > 0 ? "success" : "info", title: `${r.imported} contact${r.imported === 1 ? "" : "s"} imported (${r.format})`,
        description: `${notes ? `${notes}. ` : ""}Only names and e-mail addresses were kept - no phone numbers.` });
      refreshContacts();
    } catch (err) {
      notify({ variant: "warning", title: "Could not import", description: err instanceof Error ? err.message : "Please try again." });
    } finally {
      setImporting(false);
    }
  }

  async function handleDeleteAllContacts() {
    if (!window.confirm(`Remove all ${contacts.length} saved contacts? This cannot be undone.`)) return;
    try {
      const r = await deleteAllContacts();
      setContacts([]);
      notify({ variant: "success", title: `${r.removed} contacts removed` });
    } catch (err) {
      notify({ variant: "warning", title: "Could not remove", description: err instanceof Error ? err.message : "Please try again." });
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
        setSensitivity(({ low: "conservative", high: "aggressive" } as Record<string, string>)[s.sensitivity] ?? s.sensitivity);
        setCriticalAlerts(s.notificationsEnabled);
        setDashboardNotifs(s.emailNotifications);
        setAutomaticAlerts(s.automaticAlerts === "same" ? "same" : "critical");
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
        automaticAlerts,
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
      <PageHeader title="Settings" subtitle="Alerts, automatic protection, alert channels, activity log and trusted contacts." />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <Card className="lg:col-span-2">
          <CardHeader title="Alerts" subtitle="When CyberGuard tells you (and your alert channels) about a threat. Detection itself is never weakened."
                      icon={<ICONS.bell size={16} />} />
          <CardBody>
            <div className="pb-4">
              <label htmlFor="sensitivity" className="block text-sm font-medium text-white mb-1.5">Alert sensitivity</label>
              <select
                id="sensitivity"
                value={sensitivity}
                onChange={(e) => setSensitivity(e.target.value)}
                className="w-full rounded-lg bg-elevated border border-strong px-3 py-2.5 text-sm text-white focus-ring"
              >
                <option value="conservative">Conservative — alert only for critical threats (risk 86+)</option>
                <option value="balanced">Balanced — alert for high risk and critical (risk 71+), recommended</option>
                <option value="aggressive">Aggressive — also alert for suspicious items (risk 51+)</option>
              </select>
              <p className="text-xs text-slate-500 mt-1.5">Every scan is still analysed and saved the same way; this only decides which ones send an alert.</p>
            </div>
            <div className="pb-4">
              <label htmlFor="automatic-alerts" className="block text-sm font-medium text-white mb-1.5">Alerts for automatic protection</label>
              <select
                id="automatic-alerts"
                value={automaticAlerts}
                onChange={(e) => setAutomaticAlerts(e.target.value === "same" ? "same" : "critical")}
                className="w-full rounded-lg bg-elevated border border-strong px-3 py-2.5 text-sm text-white focus-ring"
              >
                <option value="critical">Critical only (risk 86+), recommended</option>
                <option value="same">Same level as my own scans</option>
              </select>
              <p className="text-xs text-slate-500 mt-1.5">
                For what the background watchers find by themselves (Gmail, Downloads, sign-ins). At most 5 such alerts
                are sent per hour; after that one short notice, and the rest are shown on the dashboard.
              </p>
            </div>
            <Toggle checked={criticalAlerts} onChange={setCriticalAlerts} label="Send alerts" hint="Telegram / email / WhatsApp alerts for threats at the level above" />
            <Toggle checked={dashboardNotifs} onChange={setDashboardNotifs} label="Email alerts" hint="Also send alerts by email (when email is set up below)" />
          </CardBody>
        </Card>

        <AutomationCard />

        <BrowserExtensionCard />

        <FileQuarantineCard />

        <AlertChannelsCard />

        <ActivityLogCard />

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
              <TextInput label="Their email (optional)" placeholder="e.g. teacher@college.example" value={newContactEmail} onChange={(e) => setNewContactEmail(e.target.value)} />
              <button
                onClick={handleAddContact}
                disabled={addingContact || !newContactName.trim()}
                className="rounded-lg bg-cyan-500 text-slate-950 font-medium px-4 py-2.5 text-sm hover:bg-cyan-400 focus-ring disabled:opacity-50 h-fit"
              >
                {addingContact ? "Adding..." : "Add Contact"}
              </button>
            </div>

            {/* (11 Nov) import from a phone / Google / Outlook export */}
            <div className="rounded-lg border border-default bg-elevated/40 p-3 mb-4">
              <div className="flex flex-wrap items-center gap-3">
                <label className={`rounded-lg border border-cyan-500/50 text-cyan-300 font-medium px-4 py-2 text-sm hover:bg-cyan-500/10 focus-within:ring-2 focus-within:ring-cyan-400 cursor-pointer ${importing ? "opacity-50 pointer-events-none" : ""}`}>
                  {importing ? "Importing..." : "Import contacts (.vcf or .csv)"}
                  <input type="file" accept=".vcf,.csv,text/vcard,text/csv" className="sr-only" disabled={importing}
                    onChange={(e) => { void handleImportContacts(e.target.files?.[0]); e.target.value = ""; }} />
                </label>
                <button type="button" className="text-xs text-cyan-300 hover:underline focus-ring rounded" onClick={() => setShowImportHelp((v) => !v)}>
                  {showImportHelp ? "Hide" : "How do I get this file?"}
                </button>
                <p className="text-xs text-fg-muted flex-1 min-w-[14rem]">
                  Only names and e-mail addresses are saved. Phone numbers, photos and notes in the file are ignored, and the file itself is not kept.
                </p>
              </div>
              {showImportHelp && (
                <ul className="text-xs text-fg-muted mt-3 space-y-1 list-disc pl-5">
                  <li><span className="text-fg">Android phone:</span> Contacts app → Fix &amp; manage (or ⋮ menu) → Export to file → saves <code>contacts.vcf</code>. Send it to this computer.</li>
                  <li><span className="text-fg">Google Contacts:</span> contacts.google.com → Export → "Google CSV" or "vCard".</li>
                  <li><span className="text-fg">iPhone:</span> icloud.com → Contacts → select all → Export vCard.</li>
                  <li><span className="text-fg">Outlook:</span> People → Manage contacts → Export contacts (CSV).</li>
                  <li>Up to 2,000 contacts per file (2 MB). Importing the same file twice adds nothing twice.</li>
                </ul>
              )}
            </div>

            {contactsLoading ? (
              <p className="text-sm text-fg-muted py-3">Loading contacts...</p>
            ) : contacts.length === 0 ? (
              <p className="text-sm text-fg-muted py-3">
                No contacts saved yet. Add someone above — a boss, a professor, a relative — so messages
                claiming to be from them can be checked against what you actually know about them.
              </p>
            ) : (
              <>
              <div className="flex flex-wrap items-center gap-3 mb-2">
                <p className="text-xs text-fg-muted">{contacts.length} saved</p>
                {contacts.length > 8 && (
                  <input value={contactFilter} onChange={(e) => setContactFilter(e.target.value)} placeholder="Find a contact"
                    aria-label="Find a contact"
                    className="rounded-lg bg-elevated border border-strong px-3 py-1.5 text-xs text-white focus-ring flex-1 min-w-[10rem] max-w-xs" />
                )}
                <button type="button" onClick={handleDeleteAllContacts} className="ml-auto text-xs text-red-300 hover:underline focus-ring rounded">
                  Remove all
                </button>
              </div>
              <div className="divide-y border-t border-default mt-1 max-h-80 overflow-y-auto">
                {contacts.filter((c) => !contactFilter.trim()
                  || `${c.displayName} ${c.authorizedEmail} ${c.authorizedDomain}`.toLowerCase().includes(contactFilter.trim().toLowerCase())).map((c) => (
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
              </>
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
