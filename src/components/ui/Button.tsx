import { forwardRef, type ButtonHTMLAttributes } from "react";
import { cn } from "@/lib/utils";

type Variant = "primary" | "secondary" | "ghost" | "danger" | "outline";
type Size = "sm" | "md" | "lg";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
}

const VARIANT_CLASSES: Record<Variant, string> = {
  primary: "bg-cyan-500 text-slate-950 hover:bg-cyan-400 shadow-[0_0_0_1px_rgba(34,211,238,0.3)]",
  secondary: "bg-elevated text-white hover:bg-hover-surface border border-strong",
  ghost: "text-slate-300 hover:bg-elevated hover:text-white",
  danger: "bg-red-500 text-white hover:bg-red-400",
  outline: "border border-strong text-slate-200 hover:bg-elevated bg-transparent",
};

const SIZE_CLASSES: Record<Size, string> = {
  sm: "text-xs px-2.5 py-1.5 gap-1.5",
  md: "text-sm px-3.5 py-2 gap-2",
  lg: "text-sm px-5 py-2.5 gap-2",
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = "primary", size = "md", disabled, children, ...props }, ref) => {
    return (
      <button
        ref={ref}
        disabled={disabled}
        className={cn(
          "inline-flex items-center justify-center rounded-lg font-medium transition-colors duration-150 focus-ring disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap",
          VARIANT_CLASSES[variant],
          SIZE_CLASSES[size],
          className
        )}
        {...props}
      >
        {children}
      </button>
    );
  }
);
Button.displayName = "Button";
