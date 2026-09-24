import { forwardRef, type InputHTMLAttributes, type TextareaHTMLAttributes } from "react";
import { cn } from "@/lib/utils";

interface FieldWrapProps {
  label?: string;
  hint?: string;
  error?: string;
  required?: boolean;
  htmlFor?: string;
}

function FieldChrome({ label, hint, error, required, htmlFor, children }: FieldWrapProps & { children: React.ReactNode }) {
  return (
    <div className="w-full">
      {label && (
        <label htmlFor={htmlFor} className="block text-xs font-medium text-slate-300 mb-1.5">
          {label} {required && <span className="text-red-400">*</span>}
        </label>
      )}
      {children}
      {hint && !error && <p className="text-xs text-slate-500 mt-1">{hint}</p>}
      {error && (
        <p className="text-xs text-red-400 mt-1 flex items-center gap-1" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}

type InputProps = InputHTMLAttributes<HTMLInputElement> & FieldWrapProps;

export const TextInput = forwardRef<HTMLInputElement, InputProps>(
  ({ label, hint, error, required, className, id, ...props }, ref) => (
    <FieldChrome label={label} hint={hint} error={error} required={required} htmlFor={id}>
      <input
        ref={ref}
        id={id}
        className={cn(
          "w-full rounded-lg bg-elevated border px-3 py-2.5 text-sm text-white placeholder:text-slate-600 focus-ring transition-colors",
          error ? "border-red-500/60" : "border-strong",
          className
        )}
        aria-invalid={!!error}
        {...props}
      />
    </FieldChrome>
  )
);
TextInput.displayName = "TextInput";

type TextareaProps = TextareaHTMLAttributes<HTMLTextAreaElement> & FieldWrapProps;

export const TextArea = forwardRef<HTMLTextAreaElement, TextareaProps>(
  ({ label, hint, error, required, className, id, ...props }, ref) => (
    <FieldChrome label={label} hint={hint} error={error} required={required} htmlFor={id}>
      <textarea
        ref={ref}
        id={id}
        className={cn(
          "w-full rounded-lg bg-elevated border px-3 py-2.5 text-sm text-white placeholder:text-slate-600 focus-ring transition-colors resize-y min-h-[120px]",
          error ? "border-red-500/60" : "border-strong",
          className
        )}
        aria-invalid={!!error}
        {...props}
      />
    </FieldChrome>
  )
);
TextArea.displayName = "TextArea";
