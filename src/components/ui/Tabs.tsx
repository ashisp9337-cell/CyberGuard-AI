import { cn } from "@/lib/utils";

export interface TabOption<T extends string> {
  value: T;
  label: string;
}

export function Tabs<T extends string>({ options, value, onChange, size = "md" }: { options: TabOption<T>[]; value: T; onChange: (v: T) => void; size?: "sm" | "md" }) {
  return (
    <div role="tablist" className="inline-flex items-center rounded-lg bg-elevated border border-default p-1 gap-1">
      {options.map((opt) => (
        <button
          key={opt.value}
          role="tab"
          aria-selected={value === opt.value}
          onClick={() => onChange(opt.value)}
          className={cn(
            "rounded-md font-medium transition-colors focus-ring",
            size === "sm" ? "px-2.5 py-1 text-xs" : "px-3.5 py-1.5 text-sm",
            value === opt.value ? "bg-cyan-500 text-slate-950" : "text-slate-400 hover:text-white"
          )}
        >
          {opt.label}
        </button>
      ))}
    </div>
  );
}
