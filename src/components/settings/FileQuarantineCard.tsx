// Quarantined downloads: dangerous new downloads that CyberGuard MOVED (never deleted) out of the Downloads folder.
// "Restore" moves a file back to exactly where it was. Administrator only (these are files on the owner's PC).
import { useCallback, useEffect, useState } from "react";
import { ApiError } from "@/services/api/client";
import { AdminOnlyCard } from "@/components/settings/AdminOnlyCard";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { useToast } from "@/context/ToastContext";
import { ICONS } from "@/lib/icons";
import { CLASSIFICATION_META, classifyRisk } from "@/lib/severity";
import { fetchFileQuarantine, restoreFile, type FileQuarantineList, type QuarantinedFile } from "@/services/api/quarantineService";

function when(iso: string | null): string {
  return iso ? new Date(iso).toLocaleString() : "";
}

function kb(bytes: number): string {
  return bytes >= 1048576 ? `${(bytes / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(bytes / 1024))} KB`;
}

export function FileQuarantineCard() {
  const { notify } = useToast();
  const [data, setData] = useState<FileQuarantineList | null>(null);
  const [denied, setDenied] = useState(false);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(() => {
    return fetchFileQuarantine("quarantined")
      .then(setData)
      .catch((e) => {
        if (e instanceof ApiError && e.status === 403) setDenied(true);
      })
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function restore(item: QuarantinedFile) {
    if (!window.confirm(`Put "${item.name}" back in its folder? It scored ${item.score}/100. Only do this if you trust where it came from.`)) return;
    setBusy(item.id);
    try {
      const out = await restoreFile(item.id);
      notify({ variant: "success", title: "File restored", description: out.restoredTo ?? undefined });
      await load();
    } catch (err) {
      notify({ variant: "critical", title: "Restore failed", description: err instanceof Error ? err.message : "Please try again." });
    } finally {
      setBusy(null);
    }
  }

  if (denied) {
    return <AdminOnlyCard title="Quarantined Downloads" what="Dangerous downloads moved out of the Downloads folder" />;
  }

  const items = data?.items ?? [];

  return (
    <Card className="lg:col-span-2">
      <CardHeader
        title="Quarantined Downloads"
        subtitle={data
          ? (data.enabled
            ? `New downloads scoring ${data.minScore}+ are moved here (never deleted) · ${data.counts.quarantined} held · ${data.counts.restored} restored`
            : "File quarantine is switched off (FILE_QUARANTINE=false): dangerous downloads are only reported")
          : "Dangerous downloads moved out of the Downloads folder"}
        icon={<ICONS.fileWarning size={16} />}
      />
      <CardBody>
        {loading ? (
          <div className="py-6 text-center text-sm text-fg-muted">Loading…</div>
        ) : items.length === 0 ? (
          <div className="py-6 text-center text-sm text-fg-muted">No downloads in quarantine.</div>
        ) : (
          <ul className="space-y-2">
            {items.map((item) => {
              const meta = CLASSIFICATION_META[classifyRisk(item.score)];
              return (
                <li key={item.id} className="rounded-lg border border-default bg-elevated p-3">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-white truncate" title={item.name}>{item.name}</p>
                      <p className="text-xs text-slate-500 truncate font-mono" title={item.originalPath}>from {item.originalPath}</p>
                    </div>
                    <span className="shrink-0 text-xs font-mono font-semibold" style={{ color: meta.color }}>{item.score}</span>
                  </div>
                  <p className="text-[10px] text-slate-500 mt-1 break-words">{item.reason}</p>
                  <p className="text-[10px] text-slate-500 mt-0.5">
                    {kb(item.size)} · moved {when(item.quarantinedAt)} · SHA-256 <span className="font-mono">{item.sha256.slice(0, 16)}…</span>
                  </p>
                  <div className="mt-2">
                    <button
                      disabled={busy === item.id}
                      onClick={() => restore(item)}
                      className="rounded-md border border-default px-2.5 py-1 text-xs text-slate-300 hover:text-white focus-ring disabled:opacity-50"
                    >
                      Restore
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
