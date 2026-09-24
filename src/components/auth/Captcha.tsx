import { useEffect, useId, useRef, useState } from "react";
import { AUTH_CONFIG } from "@/services/auth/config";
import { ICONS } from "@/lib/icons";

declare global {
  interface Window {
    turnstile?: {
      render: (container: HTMLElement, options: Record<string, unknown>) => string;
      remove: (widgetId: string) => void;
    };
  }
}

let turnstileScriptPromise: Promise<void> | null = null;
function loadTurnstileScript(): Promise<void> {
  if (turnstileScriptPromise) return turnstileScriptPromise;
  turnstileScriptPromise = new Promise((resolve, reject) => {
    if (document.getElementById("cf-turnstile-script")) return resolve();
    const script = document.createElement("script");
    script.id = "cf-turnstile-script";
    script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js";
    script.async = true;
    script.defer = true;
    script.onload = () => resolve();
    script.onerror = () => reject(new Error("Failed to load verification widget."));
    document.head.appendChild(script);
  });
  return turnstileScriptPromise;
}

/**
 * Bot-verification gate. When VITE_TURNSTILE_SITE_KEY is set, this renders
 * the real Cloudflare Turnstile widget and only reports success once
 * Cloudflare's own challenge passes. Without a site key, it falls back to a
 * clearly labeled development-mode checkbox that does NOT provide real bot
 * protection — it exists so the sign-up flow can be exercised end-to-end
 * in this prototype.
 */
interface CaptchaProps {
  onVerify: (verified: boolean) => void;
  /** Real Turnstile response token (sent to the backend for server-side
   *  verification), or a fixed dev-mode placeholder when Turnstile isn't
   *  configured. Optional so existing non-auth usages don't need to change. */
  onToken?: (token: string | null) => void;
}

export function Captcha({ onVerify, onToken }: CaptchaProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [failed, setFailed] = useState(false);
  const checkboxId = useId();

  const configured = AUTH_CONFIG.turnstile.isConfigured;

  useEffect(() => {
    if (!configured || !containerRef.current) return;
    let widgetId: string | undefined;
    let cancelled = false;

    loadTurnstileScript()
      .then(() => {
        if (cancelled || !window.turnstile || !containerRef.current) return;
        widgetId = window.turnstile.render(containerRef.current, {
          sitekey: AUTH_CONFIG.turnstile.siteKey,
          theme: "dark",
          callback: (token: string) => {
            onVerify(true);
            onToken?.(token);
          },
          "error-callback": () => {
            setFailed(true);
            onVerify(false);
            onToken?.(null);
          },
          "expired-callback": () => {
            onVerify(false);
            onToken?.(null);
          },
        });
      })
      .catch(() => setFailed(true));

    return () => {
      cancelled = true;
      if (widgetId && window.turnstile) window.turnstile.remove(widgetId);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [configured]);

  if (!configured) {
    return (
      <div className="rounded-lg border border-amber-500/25 bg-amber-500/5 p-3">
        <label htmlFor={checkboxId} className="flex items-start gap-2.5 cursor-pointer">
          <input
            id={checkboxId}
            type="checkbox"
            onChange={(e) => {
              onVerify(e.target.checked);
              onToken?.(e.target.checked ? "dev-mode-no-turnstile-configured" : null);
            }}
            className="mt-0.5 h-4 w-4 rounded border-strong bg-elevated accent-cyan-500 focus-ring"
          />
          <span className="text-xs text-slate-300">
            I'm not a robot
            <span className="block text-[10px] text-amber-400/80 mt-0.5">
              Development-mode verification — not real bot protection. Set VITE_TURNSTILE_SITE_KEY to enable Cloudflare Turnstile.
            </span>
          </span>
        </label>
      </div>
    );
  }

  if (failed) {
    return (
      <p className="text-xs text-red-400 flex items-center gap-1.5">
        <ICONS.warning size={13} /> Verification failed to load. Please refresh and try again.
      </p>
    );
  }

  return <div ref={containerRef} />;
}
