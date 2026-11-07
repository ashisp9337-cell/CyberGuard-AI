import { useEffect, useState } from "react";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { useToast } from "@/context/ToastContext";
import { ICONS } from "@/lib/icons";
import {
  createExtensionKey,
  deleteExtensionKey,
  listExtensionKeys,
  type ExtensionKey,
  type NewExtensionKey,
} from "@/services/api/extensionService";

function when(iso: string | null): string {
  return iso ? new Date(iso).toLocaleString() : "never";
}

/** (6 Nov) Connect the CyberGuard browser extension (Chrome, Edge, Brave, Opera, Firefox) to this account. */
export function BrowserExtensionCard() {
  const { notify } = useToast();
  const [keys, setKeys] = useState<ExtensionKey[] | null>(null);
  const [label, setLabel] = useState("My browser");
  const [fresh, setFresh] = useState<NewExtensionKey | null>(null);
  const [busy, setBusy] = useState(false);

  const load = () => listExtensionKeys().then(setKeys).catch(() => setKeys([]));
  useEffect(() => {
    load();
  }, []);

  async function connect() {
    setBusy(true);
    try {
      setFresh(await createExtensionKey(label.trim() || "My browser"));
      await load();
    } catch (err) {
      notify({ variant: "critical", title: "Could not make a key", description: err instanceof Error ? err.message : "" });
    } finally {
      setBusy(false);
    }
  }

  async function remove(k: ExtensionKey) {
    setBusy(true);
    try {
      await deleteExtensionKey(k.id);
      notify({ variant: "success", title: `${k.label} disconnected`, description: "That browser can no longer use CyberGuard." });
      await load();
    } catch (err) {
      notify({ variant: "critical", title: "Could not delete the key", description: err instanceof Error ? err.message : "" });
    } finally {
      setBusy(false);
    }
  }

  async function copy() {
    if (!fresh) return;
    try {
      await navigator.clipboard.writeText(fresh.token);
      notify({ variant: "success", title: "Key copied", description: "Paste it into the extension's settings." });
    } catch {
      notify({ variant: "warning", title: "Copy it by hand", description: "Select the key and press Ctrl+C." });
    }
  }

  return (
    <Card className="lg:col-span-2">
      <CardHeader
        title="Browser extension"
        subtitle="Warns you before a dangerous website opens - in Chrome, Edge, Brave, Opera and Firefox. The extension asks this CyberGuard (on your computer) and nothing else."
        icon={<ICONS.threatIntel size={16} />}
      />
      <CardBody>
        <ol className="text-xs text-slate-400 list-decimal ml-4 space-y-1">
          <li>Install it from the <span className="font-mono text-slate-300">browser-extension</span> folder of the project (Chrome: chrome://extensions → Developer mode → Load unpacked; Firefox: about:debugging → Load Temporary Add-on).</li>
          <li>Make a key below and paste it into the extension's settings page, then press Connect.</li>
          <li>Switch on “Check each website I open” there (and, if you want, “Also check login pages”).</li>
        </ol>

        <div className="mt-3 flex flex-wrap items-end gap-2">
          <label className="text-xs text-slate-400">
            Name of this browser
            <input value={label} maxLength={60} onChange={(e) => setLabel(e.target.value)}
              className="mt-1 block w-56 rounded-lg border border-default bg-elevated px-3 py-1.5 text-sm text-white focus-ring" />
          </label>
          <button onClick={connect} disabled={busy}
            className="rounded-lg bg-cyan-500 text-slate-950 font-semibold px-3 py-2 text-xs hover:bg-cyan-400 focus-ring disabled:opacity-50">
            Connect a browser
          </button>
        </div>

        {fresh && (
          <div className="mt-3 rounded-md border border-amber-500/40 bg-amber-500/5 p-3">
            <p className="text-xs font-semibold text-amber-300">Key for “{fresh.label}” - shown only this once</p>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <code className="font-mono text-xs text-white break-all bg-elevated rounded px-2 py-1 select-all">{fresh.token}</code>
              <button onClick={copy} className="rounded-lg border border-cyan-500/50 text-cyan-300 px-3 py-1 text-xs hover:bg-cyan-500/10 focus-ring">
                Copy
              </button>
              <button onClick={() => setFresh(null)} className="rounded-lg border border-default text-slate-300 px-3 py-1 text-xs hover:bg-elevated focus-ring">
                Done
              </button>
            </div>
            <p className="text-[11px] text-slate-500 mt-1">Treat it like a password. Lost it? Delete it below and make a new one.</p>
          </div>
        )}

        <div className="mt-3">
          <p className="text-[11px] uppercase tracking-wide text-slate-500 mb-1">Connected browsers</p>
          {keys === null ? (
            <p className="text-xs text-slate-500">Loading…</p>
          ) : keys.length === 0 ? (
            <p className="text-xs text-slate-500">None yet.</p>
          ) : (
            <ul className="space-y-1">
              {keys.map((k) => (
                <li key={k.id} className="flex items-center justify-between gap-2 rounded-md border border-default bg-elevated/40 px-3 py-2 text-xs">
                  <span className="text-slate-200">{k.label}</span>
                  <span className="text-slate-500">made {when(k.createdAt)} · last used {when(k.lastUsedAt)}</span>
                  <button onClick={() => remove(k)} disabled={busy}
                    className="rounded-lg border border-red-500/40 text-red-300 px-2 py-1 hover:bg-red-500/10 focus-ring disabled:opacity-50">
                    Disconnect
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </CardBody>
    </Card>
  );
}
