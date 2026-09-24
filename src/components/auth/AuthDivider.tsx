export function AuthDivider({ label = "OR CONTINUE WITH EMAIL" }: { label?: string }) {
  return (
    <div className="flex items-center gap-3 my-5" role="separator">
      <span className="h-px flex-1 bg-[var(--color-border-strong)]" />
      <span className="text-[10px] font-semibold tracking-wider text-slate-500 whitespace-nowrap">{label}</span>
      <span className="h-px flex-1 bg-[var(--color-border-strong)]" />
    </div>
  );
}
