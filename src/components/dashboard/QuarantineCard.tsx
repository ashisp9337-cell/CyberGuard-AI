import { useCallback, useEffect, useState } from "react";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { useToast } from "@/context/ToastContext";
import { fetchQuarantine, quarantineAction, type QuarantineList, type QuarantinedEmail } from "@/services/api/quarantineService";
import { CLASSIFICATION_META, classifyRisk } from "@/lib/severity";
import { ICONS } from "@/lib/icons";

export function QuarantineCard() {
  const { notify } = useToast();
  const [data, setData] = useState<QuarantineList | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(() => {
    return fetchQuarantine("quarantined", 6)
      .then(setData)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function act(item: QuarantinedEmail, action: "release" | "delete") {
    if (action === "release" && item.riskScore >= 86 &&
        !window.confirm(`This email scored ${item.riskScore}/100 (critical). Release it anyway?`)) return;
    setBusy(item.id);
    try {
      await quarantineAction(item.id, action);
      notify({ variant: "success", title: action === "release" ? "Email released" : "Email deleted" });
      await load();
    } catch (err) {
      notify({ variant: "critical", title: "Action failed", description: err instanceof Error ? err.message : "Please try again." });
    } finally {
      setBusy(null);
    }
  }

  const items = data?.items ?? [];

  return (
    <Card>
      <CardHeader
        title="Email Quarantine"
        subtitle={data ? `${data.counts.quarantined} held · ${data.counts.released} released · ${data.counts.deleted} deleted` : "Dangerous emails held automatically"}
        icon={<ICONS.lock size={16} />}
      />
      <CardBody>
        {loading ? (
          <div className="py-6 text-center text-sm text-fg-muted">Loading…</div>
        ) : items.length === 0 ? (
          <div className="py-6 text-center text-sm text-fg-muted">Quarantine is empty. Emails scoring 71+ are held here automatically.</div>
        ) : (
          <ul className="space-y-2">
            {items.map((item) => {
              const meta = CLASSIFICATION_META[classifyRisk(item.riskScore)];
              return (
                <li key={item.id} className="rounded-lg border border-default bg-elevated p-3">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-white truncate" title={item.subject}>{item.subject || "(no subject)"}</p>
                      <p className="text-xs text-slate-500 truncate font-mono" title={item.from}>{item.from}</p>
                    </div>
                    <span className="shrink-0 text-xs font-mono font-semibold" style={{ color: meta.color }}>{item.riskScore}</span>
                  </div>
                  <p className="text-[10px] text-slate-500 mt-1 truncate" title={item.reason}>{item.category}</p>
                  <div className="mt-2 flex gap-2">
                    <button
                      disabled={busy === item.id}
                      onClick={() => act(item, "release")}
                      className="rounded-md border border-default px-2.5 py-1 text-xs text-slate-300 hover:text-white focus-ring disabled:opacity-50"
                    >
                      Release
                    </button>
                    <button
                      disabled={busy === item.id}
                      onClick={() => act(item, "delete")}
                      className="rounded-md px-2.5 py-1 text-xs font-medium focus-ring disabled:opacity-50"
                      style={{ color: "var(--color-critical)", backgroundColor: "var(--color-critical-bg)" }}
                    >
                      Delete
                    </button>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </CardBody>
    </Card>
  );
}
