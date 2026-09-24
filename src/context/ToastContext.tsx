import { createContext, useCallback, useContext, useState, type ReactNode } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { ICONS } from "@/lib/icons";
import { generateId } from "@/lib/utils";

export type ToastVariant = "success" | "info" | "warning" | "critical";

export interface ToastItem {
  id: string;
  title: string;
  description?: string;
  variant: ToastVariant;
}

interface ToastContextValue {
  notify: (toast: Omit<ToastItem, "id">) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

const VARIANT_META: Record<ToastVariant, { icon: keyof typeof ICONS; color: string; bg: string }> = {
  success: { icon: "success", color: "var(--color-safe)", bg: "var(--color-safe-bg)" },
  info: { icon: "info", color: "var(--color-info)", bg: "var(--color-info-bg)" },
  warning: { icon: "warning", color: "var(--color-warning)", bg: "var(--color-warning-bg)" },
  critical: { icon: "critical", color: "var(--color-critical)", bg: "var(--color-critical-bg)" },
};

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const notify = useCallback((toast: Omit<ToastItem, "id">) => {
    const id = generateId("TST");
    setToasts((prev) => [...prev, { ...toast, id }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 4500);
  }, []);

  const dismiss = (id: string) => setToasts((prev) => prev.filter((t) => t.id !== id));

  return (
    <ToastContext.Provider value={{ notify }}>
      {children}
      <div className="fixed bottom-4 right-4 z-[100] flex flex-col gap-2 w-[340px] max-w-[90vw]">
        <AnimatePresence>
          {toasts.map((t) => {
            const meta = VARIANT_META[t.variant];
            const Icon = ICONS[meta.icon];
            return (
              <motion.div
                key={t.id}
                initial={{ opacity: 0, y: 12, scale: 0.96 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, x: 40 }}
                transition={{ duration: 0.2 }}
                role="status"
                className="rounded-lg border border-default bg-elevated shadow-xl p-3 flex items-start gap-3"
                style={{ borderLeft: `3px solid ${meta.color}` }}
              >
                <div
                  className="mt-0.5 shrink-0 h-7 w-7 rounded-md flex items-center justify-center"
                  style={{ backgroundColor: meta.bg, color: meta.color }}
                >
                  <Icon size={15} />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-white leading-tight">{t.title}</p>
                  {t.description && (
                    <p className="text-xs text-slate-400 mt-0.5 leading-snug">{t.description}</p>
                  )}
                </div>
                <button
                  onClick={() => dismiss(t.id)}
                  aria-label="Dismiss notification"
                  className="text-slate-500 hover:text-slate-300 focus-ring rounded"
                >
                  <ICONS.close size={14} />
                </button>
              </motion.div>
            );
          })}
        </AnimatePresence>
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used within ToastProvider");
  return ctx;
}
