import { useState } from "react";
import { AUTH_CONFIG } from "@/services/auth/config";
import { useAuth } from "@/context/AuthContext";
import { ICONS } from "@/lib/icons";
import { cn } from "@/lib/utils";

function GoogleLogo() {
  return (
    <svg width="16" height="16" viewBox="0 0 48 48" aria-hidden="true">
      <path fill="#FFC107" d="M43.6 20.5H42V20.4H24v7.2h11.3c-1.6 4.5-5.9 7.7-11.3 7.7-6.9 0-12.4-5.6-12.4-12.4S17.1 10.5 24 10.5c3.2 0 6 1.2 8.2 3.1l5.4-5.4C34.4 5 29.5 3 24 3 12.4 3 3 12.4 3 24s9.4 21 21 21 21-9.4 21-21c0-1.2-.1-2.4-.4-3.5z" />
      <path fill="#FF3D00" d="m6.3 14.7 5.9 4.3C13.8 15.4 18.5 12.5 24 12.5c3.2 0 6 1.2 8.2 3.1l5.4-5.4C34.4 6 29.5 4 24 4 16 4 9.1 8.4 6.3 14.7z" />
      <path fill="#4CAF50" d="M24 44c5.4 0 10.2-1.8 14-5l-6.5-5.4c-2 1.4-4.6 2.3-7.5 2.3-5.4 0-9.9-3.4-11.4-8.1l-6.1 4.7C9 39.5 15.9 44 24 44z" />
      <path fill="#1976D2" d="M43.6 20.5H42V20.4H24v7.2h11.3c-.9 2.5-2.5 4.6-4.6 6.1l6.5 5.4C39.6 37.3 44 31.6 44 24c0-1.2-.1-2.4-.4-3.5z" />
    </svg>
  );
}

export function GoogleSignInButton({ label = "Continue with Google", onError }: { label?: string; onError?: (message: string) => void }) {
  const { signInWithGoogle } = useAuth();
  const [loading, setLoading] = useState(false);
  const configured = AUTH_CONFIG.google.isConfigured;

  async function handleClick() {
    setLoading(true);
    try {
      await signInWithGoogle();
    } catch (err) {
      onError?.(err instanceof Error ? err.message : "Google Sign-In failed.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <button
      type="button"
      onClick={handleClick}
      disabled={!configured || loading}
      title={!configured ? "Google Sign-In isn't configured for this environment (VITE_GOOGLE_CLIENT_ID missing)." : undefined}
      className={cn(
        "w-full flex items-center justify-center gap-2.5 rounded-lg border border-strong bg-elevated py-2.5 text-sm font-medium text-white transition-colors focus-ring",
        configured && !loading ? "hover:bg-hover-surface" : "opacity-50 cursor-not-allowed"
      )}
    >
      {loading ? <ICONS.loader size={16} className="animate-spin" /> : <GoogleLogo />}
      {label}
    </button>
  );
}
