import { useEffect, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { AUTH_CONFIG } from "@/services/auth/config";
import { backendAuthService } from "@/services/auth/backendAuthService";
import { useAuth } from "@/context/AuthContext";
import { ICONS } from "@/lib/icons";

/** (9 Nov) Google sign-in is offered only when the backend is used AND a Google client ID is configured. */
export const googleSignInEnabled = AUTH_CONFIG.isBackend && AUTH_CONFIG.google.isConfigured;

let gisPromise: Promise<any> | null = null;

/** Google Identity Services, loaded once from Google (resolves with window.google when it is ready). */
function loadGoogleIdentity(): Promise<any> {
  if (gisPromise) return gisPromise;
  gisPromise = new Promise((resolve, reject) => {
    const ready = () => (window as any).google?.accounts?.id;
    if (ready()) return resolve((window as any).google);
    let script = document.getElementById("google-identity-services") as HTMLScriptElement | null;
    if (!script) {
      script = document.createElement("script");
      script.id = "google-identity-services";
      script.src = "https://accounts.google.com/gsi/client";
      script.async = true;
      script.defer = true;
      document.head.appendChild(script);
    }
    const started = Date.now();
    const wait = () => {
      if (ready()) return resolve((window as any).google);
      if (Date.now() - started > 15000) {
        gisPromise = null;
        return reject(new Error("Google Sign-In could not be loaded. Check the internet connection."));
      }
      window.setTimeout(wait, 100);
    };
    script.addEventListener("error", () => {
      gisPromise = null;
      reject(new Error("Google Sign-In could not be loaded. Check the internet connection."));
    });
    wait();
  });
  return gisPromise;
}

/**
 * (9 Nov) Google's own "Sign in with Google" button (it opens Google's sign-in popup - more reliable than the One Tap
 * prompt, which Google hides for a while after it was closed once). The credential Google returns is checked by OUR
 * backend against Google's keys (backend/app/core/security.py) and the company's sign-up rule, then the session starts.
 * Renders nothing when Google sign-in is not configured.
 */
export function GoogleSignInButton({ label = "Continue with Google", onError }: { label?: string; onError?: (message: string) => void }) {
  const { acceptSignedInUser } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const holder = useRef<HTMLDivElement>(null);
  const [busy, setBusy] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const redirectTo = (location.state as { from?: string } | null)?.from ?? "/dashboard";
  const errorRef = useRef(onError);
  errorRef.current = onError;

  useEffect(() => {
    if (!googleSignInEnabled) return;
    let alive = true;
    loadGoogleIdentity()
      .then((google) => {
        if (!alive || !holder.current) return;
        google.accounts.id.initialize({
          client_id: AUTH_CONFIG.google.clientId,
          ux_mode: "popup",
          callback: async (response: { credential?: string }) => {
            if (!response?.credential) return;
            setBusy(true);
            try {
              const { user } = await backendAuthService.signInWithGoogleCredential(response.credential);
              acceptSignedInUser(user);
              navigate(redirectTo, { replace: true });
            } catch (err) {
              errorRef.current?.(err instanceof Error ? err.message : "Google sign-in failed.");
            } finally {
              setBusy(false);
            }
          },
        });
        const width = Math.max(200, Math.min(400, Math.round(holder.current.getBoundingClientRect().width || 320)));
        google.accounts.id.renderButton(holder.current, {
          type: "standard", theme: "filled_black", size: "large", shape: "rectangular", logo_alignment: "left",
          text: /up/i.test(label) ? "signup_with" : "continue_with", width,
        });
        setLoaded(true);
      })
      .catch((err) => errorRef.current?.(err instanceof Error ? err.message : "Google Sign-In could not be loaded."));
    return () => {
      alive = false;
    };
  }, [acceptSignedInUser, navigate, redirectTo, label]);

  if (!googleSignInEnabled) return null;
  return (
    <div className="w-full">
      <div className="relative">
        <div ref={holder} className="w-full flex justify-center min-h-[44px]" aria-label={label} />
        {!loaded && (
          <p className="absolute inset-0 flex items-center justify-center text-xs text-slate-500 pointer-events-none">
            Loading Google sign-in…
          </p>
        )}
      </div>
      {busy && (
        <p className="text-xs text-slate-400 flex items-center justify-center gap-1.5 mt-2" role="status">
          <ICONS.loader size={13} className="animate-spin" /> Signing in with Google…
        </p>
      )}
    </div>
  );
}
