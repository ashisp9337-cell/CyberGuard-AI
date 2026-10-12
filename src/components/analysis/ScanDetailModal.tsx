// Full saved result of any past scan (manual or automatic): verdict, indicators, MITRE ATT&CK
// techniques, seen-before matches, engine breakdown and recommendations (GET /api/scans/{id}).
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ResultView } from "@/components/analysis/ResultView";
import { getScan } from "@/services/api/scansService";
import { ICONS } from "@/lib/icons";
import type { AnalysisResult } from "@/types";

export function ScanDetailModal({ scanId, onClose }: { scanId: string; onClose: () => void }) {
  const navigate = useNavigate();
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setResult(null);
    setError(null);
    getScan(scanId)
      .then((r) => !cancelled && setResult(r))
      .catch((e) => !cancelled && setError(e instanceof Error ? e.message : "Could not load this scan."));
    return () => { cancelled = true; };
  }, [scanId]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60" onClick={onClose} role="dialog" aria-modal="true" aria-label="Scan details">
      <div className="h-full w-full max-w-3xl overflow-y-auto bg-canvas border-l border-default p-4 sm:p-6" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <div>
            <p className="text-[10px] uppercase tracking-wide text-slate-500">Saved scan</p>
            <p className="text-sm text-white mono">{scanId}</p>
          </div>
          <button type="button" onClick={onClose} className="rounded-lg border border-default p-2 text-slate-400 hover:text-white" aria-label="Close">
            <ICONS.close size={16} />
          </button>
        </div>
        {error && <p className="text-sm text-red-300">{error}</p>}
        {!result && !error && (
          <div className="flex items-center gap-2 text-sm text-slate-400 py-10 justify-center">
            <ICONS.loader size={16} className="animate-spin" /> Loading scan…
          </div>
        )}
        {result && (
          <ResultView result={result} newScanLabel="Open this module"
                      onNewScan={() => { onClose(); navigate(`/modules/${result.moduleId}`); }} />
        )}
      </div>
    </div>
  );
}
