import { ICONS } from "@/lib/icons";
import { cn } from "@/lib/utils";

export interface PasswordRule {
  label: string;
  test: (pw: string) => boolean;
}

export const PASSWORD_RULES: PasswordRule[] = [
  { label: "At least 8 characters", test: (pw) => pw.length >= 8 },
  { label: "One uppercase letter", test: (pw) => /[A-Z]/.test(pw) },
  { label: "One lowercase letter", test: (pw) => /[a-z]/.test(pw) },
  { label: "One number", test: (pw) => /[0-9]/.test(pw) },
];

export function passwordMeetsRequirements(pw: string): boolean {
  return PASSWORD_RULES.every((r) => r.test(pw));
}

export function PasswordStrength({ password }: { password: string }) {
  const passed = PASSWORD_RULES.filter((r) => r.test(password)).length;
  const pct = (passed / PASSWORD_RULES.length) * 100;
  const color = pct === 100 ? "var(--color-safe)" : pct >= 50 ? "var(--color-warning)" : "var(--color-critical)";

  return (
    <div className="mt-2">
      <div className="h-1.5 w-full rounded-full bg-elevated overflow-hidden mb-2.5">
        <div className="h-full rounded-full transition-all duration-300" style={{ width: `${pct}%`, backgroundColor: color }} />
      </div>
      <ul className="grid grid-cols-2 gap-x-3 gap-y-1.5">
        {PASSWORD_RULES.map((rule) => {
          const met = rule.test(password);
          return (
            <li key={rule.label} className={cn("flex items-center gap-1.5 text-[11px]", met ? "text-emerald-400" : "text-slate-500")}>
              {met ? <ICONS.success size={12} /> : <span className="h-1 w-1 rounded-full bg-slate-600 ml-0.5 mr-0.5" />}
              {rule.label}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
