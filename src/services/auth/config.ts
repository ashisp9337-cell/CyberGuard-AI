// Centralized authentication configuration.
// AuthContext and every auth page read from here — never check
// import.meta.env directly outside this file.

export const AUTH_CONFIG = {
  // "mock" uses the local, browser-only demo auth system in
  // mockAuthService.ts. "backend" (the default) talks to the real
  // CyberGuard FastAPI backend via authService.ts.
  // A production build (npm run build) ALWAYS uses the real backend login: the browser-only demo login
  // can never be switched on in a real deployment, whatever .env says.
  provider: import.meta.env.PROD
    ? "backend"
    : (import.meta.env.VITE_AUTH_PROVIDER as string | undefined) || "backend",

  google: {
    clientId: import.meta.env.VITE_GOOGLE_CLIENT_ID ?? "",
    get isConfigured() {
      return Boolean(this.clientId);
    },
  },

  turnstile: {
    siteKey: import.meta.env.VITE_TURNSTILE_SITE_KEY ?? "",
    get isConfigured() {
      return Boolean(this.siteKey);
    },
  },

  get isMock() {
    return this.provider === "mock";
  },
  get isBackend() {
    return this.provider === "backend";
  },
} as const;
