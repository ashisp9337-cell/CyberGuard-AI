import { forwardRef, useState, type InputHTMLAttributes } from "react";
import { ICONS } from "@/lib/icons";
import { cn } from "@/lib/utils";

interface PasswordInputProps extends Omit<InputHTMLAttributes<HTMLInputElement>, "type"> {
  label?: string;
  error?: string;
  required?: boolean;
}

export const PasswordInput = forwardRef<HTMLInputElement, PasswordInputProps>(
  ({ label, error, required, className, id, ...props }, ref) => {
    const [visible, setVisible] = useState(false);
    return (
      <div className="w-full">
        {label && (
          <label htmlFor={id} className="block text-xs font-medium text-slate-300 mb-1.5">
            {label} {required && <span className="text-red-400">*</span>}
          </label>
        )}
        <div className="relative">
          <input
            ref={ref}
            id={id}
            type={visible ? "text" : "password"}
            className={cn(
              "w-full rounded-lg bg-elevated border px-3 py-2.5 pr-10 text-sm text-white placeholder:text-slate-600 focus-ring transition-colors",
              error ? "border-red-500/60" : "border-strong",
              className
            )}
            aria-invalid={!!error}
            {...props}
          />
          <button
            type="button"
            onClick={() => setVisible((v) => !v)}
            aria-label={visible ? "Hide password" : "Show password"}
            className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 focus-ring rounded p-0.5"
          >
            {visible ? <ICONS.eyeOff size={16} /> : <ICONS.eye size={16} />}
          </button>
        </div>
        {error && (
          <p className="text-xs text-red-400 mt-1" role="alert">
            {error}
          </p>
        )}
      </div>
    );
  }
);
PasswordInput.displayName = "PasswordInput";
