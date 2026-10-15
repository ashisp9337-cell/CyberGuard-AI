import { useEffect, useState } from "react";
import { ApiError } from "@/services/api/client";
import { AdminOnlyCard } from "@/components/settings/AdminOnlyCard";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { useToast } from "@/context/ToastContext";
import { getAlertStatus, sendTestAlert, type AlertChannelStatus, type AlertSendResult } from "@/services/api/alertsService";
import { ICONS } from "@/lib/icons";

const CHANNELS: { key: "telegram" | "email" | "whatsapp"; label: string; icon: keyof typeof ICONS; setup: string }[] = [
  { key: "telegram", label: "Telegram", icon: "message", setup: "TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID" },
  { key: "email", label: "Email", icon: "email", setup: "SMTP_HOST, SMTP_USER, SMTP_PASSWORD, ALERT_EMAIL_TO" },
  { key: "whatsapp", label: "WhatsApp", icon: "message", setup: "WHATSAPP_TO + CALLMEBOT_APIKEY (or Twilio keys)" },
];

const RESULT_TEXT: Record<string, string> = {
  sent: "Sent",
  failed: "Failed",
  not_configured: "Not set up",
  disabled_by_user: "Turned off",
};

export function AlertChannelsCard() {
  const { notify } = useToast();
  const [status, setStatus] = useState<AlertChannelStatus | null>(null);
  const [results, setResults] = useState<AlertSendResult[]>([]);
  const [sending, setSending] = useState(false);
  const [adminOnly, setAdminOnly] = useState(false);

  useEffect(() => {
    getAlertStatus().then(setStatus).catch((e) => {
      setStatus(null);
      if (e instanceof ApiError && e.status === 403) setAdminOnly(true);
    });
  }, []);

  async function handleTest() {
    setSending(true);
    try {
      const res = await sendTestAlert();
      setStatus(res.channels);
      setResults(res.results);
      const sent = res.results.filter((r) => r.status === "sent").map((r) => r.channel);
      notify(
        sent.length
          ? { variant: "success", title: "Test alert sent", description: `Check ${sent.join(", ")}.` }
          : { variant: "warning", title: "No alert was sent", description: "Set up at least one channel in backend/.env and restart the backend." },
      );
    } catch (err) {
      notify({ variant: "critical", title: "Test failed", description: err instanceof Error ? err.message : "Please try again." });
    } finally {
      setSending(false);
    }
  }

  if (adminOnly) {
    return <AdminOnlyCard title="Alert Channels" what="Telegram, email and WhatsApp alerts to the security team" />;
  }

  return (
    <Card className="lg:col-span-2">
      <CardHeader
        title="Alert Channels"
        subtitle={status ? `Threats scoring ${status.minScore}+ are sent automatically to every channel that is set up` : "Where CYBERGUARD sends high-risk alerts"}
        icon={<ICONS.bell size={16} />}
      />
      <CardBody>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {CHANNELS.map((c) => {
            const Icon = ICONS[c.icon];
            const on = status?.[c.key] ?? false;
            const result = results.find((r) => r.channel === c.key);
            return (
              <div key={c.key} className="rounded-lg border border-default bg-elevated/40 p-3">
                <div className="flex items-center justify-between gap-2">
                  <span className="flex items-center gap-2 text-sm font-medium text-white">
                    <Icon size={15} /> {c.label}
                    {c.key === "whatsapp" && status?.whatsapp ? (
                      <span className="text-xs text-slate-500">({status.whatsappProvider})</span>
                    ) : null}
                  </span>
                  <span className={`text-xs font-medium ${on ? "text-emerald-400" : "text-slate-500"}`}>
                    {status === null ? "…" : on ? "Connected" : "Not set up"}
                  </span>
                </div>
                {!on && <p className="text-xs text-slate-500 mt-1.5">backend/.env: {c.setup}</p>}
                {result && (
                  <p className={`text-xs mt-1.5 ${result.status === "sent" ? "text-emerald-400" : result.status === "failed" ? "text-red-400" : "text-slate-500"}`}>
                    Test: {RESULT_TEXT[result.status] ?? result.status}
                    {result.error ? ` — ${result.error}` : ""}
                  </p>
                )}
              </div>
            );
          })}
        </div>
        <div className="mt-4 flex items-center justify-between gap-3 flex-wrap">
          <p className="text-xs text-slate-500">Sends a sample alert (no real threat) to every connected channel.</p>
          <button
            onClick={handleTest}
            disabled={sending}
            className="rounded-lg border border-cyan-500/50 text-cyan-300 font-medium px-4 py-2 text-sm hover:bg-cyan-500/10 focus-ring disabled:opacity-50"
          >
            {sending ? "Sending…" : "Send test alert"}
          </button>
        </div>
      </CardBody>
    </Card>
  );
}
