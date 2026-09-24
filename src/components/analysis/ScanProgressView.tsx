import { motion } from "framer-motion";
import { STANDARD_SCAN_STAGES } from "@/services/api/analysisService";
import { ICONS } from "@/lib/icons";
import { cn } from "@/lib/utils";

export function ScanProgressView({ currentIndex }: { currentIndex: number }) {
  const total = STANDARD_SCAN_STAGES.length;
  const pct = Math.round(((currentIndex + 1) / total) * 100);

  return (
    <div className="rounded-xl border border-strong bg-surface p-6 md:p-8">
      <div className="flex flex-col items-center text-center mb-6">
        <div className="relative h-16 w-16 mb-4">
          <div className="absolute inset-0 rounded-full border-2 border-cyan-500/20" />
          <motion.div
            className="absolute inset-0 rounded-full border-2 border-transparent border-t-cyan-400"
            animate={{ rotate: 360 }}
            transition={{ repeat: Infinity, duration: 1.1, ease: "linear" }}
          />
          <div className="absolute inset-0 flex items-center justify-center">
            <ICONS.scan size={22} className="text-cyan-400" />
          </div>
        </div>
        <p className="text-sm font-semibold text-white">{STANDARD_SCAN_STAGES[currentIndex]?.label ?? "Analyzing..."}</p>
        <p className="text-xs text-slate-500 mt-1">AI-powered analysis in progress &mdash; do not close this window</p>
      </div>

      <div className="h-2 w-full rounded-full bg-elevated overflow-hidden mb-1">
        <motion.div
          className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-blue-500"
          animate={{ width: `${pct}%` }}
          transition={{ duration: 0.4, ease: "easeOut" }}
        />
      </div>
      <p className="text-right text-xs font-mono text-slate-500 mb-6">{pct}%</p>

      <ol className="space-y-1.5">
        {STANDARD_SCAN_STAGES.map((stage, idx) => {
          const state = idx < currentIndex ? "done" : idx === currentIndex ? "active" : "pending";
          return (
            <li
              key={stage.id}
              className={cn(
                "flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors",
                state === "active" && "bg-cyan-500/5"
              )}
            >
              <span
                className={cn(
                  "flex h-5 w-5 items-center justify-center rounded-full shrink-0",
                  state === "done" && "bg-emerald-500/15 text-emerald-400",
                  state === "active" && "bg-cyan-500/15 text-cyan-400",
                  state === "pending" && "bg-elevated text-slate-600"
                )}
              >
                {state === "done" ? (
                  <ICONS.success size={13} />
                ) : (
                  <span className="text-[10px] font-bold">{idx + 1}</span>
                )}
              </span>
              <span className={cn(state === "pending" ? "text-slate-600" : state === "active" ? "text-white font-medium" : "text-slate-400")}>
                {stage.label}
              </span>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
