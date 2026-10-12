// Check one URL against external threat-intelligence feeds (URLhaus, VirusTotal).
// A feed without an API key says "not configured" instead of guessing.
import { useState } from "react";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { TextInput } from "@/components/ui/Input";
import { lookupUrl, type LookupResult, type ProviderResult } from "@/services/api/threatIntelService";
import { ICONS } from "@/lib/icons";

function verdict(p: ProviderResult): { text: string; color: string } {
  if (p.status === "unavailable" || p.status === "skipped") return { text: "Not configured (add an API key in backend/.env)", color: "rgb(100 116 139)" };
  if (p.status === "error") return { text: `Could not reach the feed${p.reason ? `: ${p.reason}` : ""}`, color: "var(--color-warning)" };
  if (p.status === "not_found") return { text: "Not in this feed", color: "var(--color-safe)" };
  if (p.provider === "urlhaus") {
    return p.query_status === "ok"
      ? { text: `Listed as malicious${p.threat ? ` (${p.threat})` : ""}`, color: "var(--color-critical)" }
      : { text: "Not listed", color: "var(--color-safe)" };
  }
  if (p.provider === "virustotal" && p.stats) {
    const bad = (p.stats.malicious ?? 0) + (p.stats.suspicious ?? 0);
    return bad > 0
      ? { text: `${bad} engine(s) flag it as malicious or suspicious`, color: "var(--color-critical)" }
      : { text: "No engine flags it", color: "var(--color-safe)" };
  }
  return { text: p.status, color: "rgb(148 163 184)" };
}

export function ThreatIntelLookupCard() {
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState<LookupResult | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function check() {
    if (!url.trim()) return;
    setBusy(true); setErr(null); setRes(null);
    try {
      setRes(await lookupUrl(url.trim()));
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Lookup failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader title="Threat-Intel Lookup" subtitle="Check a link against URLhaus and VirusTotal. The link is never opened."
                  icon={<ICONS.radar size={16} />} />
      <CardBody className="space-y-3">
        <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); check(); }}>
          <div className="flex-1 min-w-0">
            <TextInput id="ti-lookup" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="http://suspicious-site.example/login" />
          </div>
          <Button type="submit" variant="primary" disabled={busy || !url.trim()}>
            {busy ? <ICONS.loader size={14} className="animate-spin" /> : <ICONS.search size={14} />} Check
          </Button>
        </form>
        {err && <p className="text-xs text-red-300">{err}</p>}
        {res && (
          <div className="space-y-2">
            {[res.urlhaus, res.virustotal].map((p) => {
              const v = verdict(p);
              return (
                <div key={p.provider} className="flex items-center justify-between gap-3 rounded-lg border border-default bg-elevated p-3">
                  <span className="text-sm font-medium text-white">{p.provider === "urlhaus" ? "URLhaus (abuse.ch)" : "VirusTotal"}</span>
                  <span className="text-xs text-right" style={{ color: v.color }}>{v.text}</span>
                </div>
              );
            })}
          </div>
        )}
      </CardBody>
    </Card>
  );
}
