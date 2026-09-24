// ---------------------------------------------------------------------------
// Authentication service abstraction.
//
//   UI (pages/components)
//        ↓
//   AuthContext
//        ↓
//   authService   ← you are here
//        ↓
//   backendAuthService (real FastAPI backend)   |   mockAuthService (demo)
//
// AuthContext never talks to a concrete implementation directly —
// everything routes through the functions below, keyed off
// AUTH_CONFIG.provider ("backend" by default, "mock" for offline UI dev).
// ---------------------------------------------------------------------------

import type { AuthResult, SignInInput, SignUpInput } from "@/types";
import { AUTH_CONFIG } from "./config";
import { mockAuthService } from "./mockAuthService";
import { backendAuthService } from "./backendAuthService";

function notImplemented(provider: string): never {
  throw new Error(
    `Auth provider "${provider}" is not implemented. Set VITE_AUTH_PROVIDER=backend (real API) or VITE_AUTH_PROVIDER=mock (offline demo).`
  );
}

export const authService = {
  async signUp(input: SignUpInput & { turnstileToken?: string }): Promise<AuthResult> {
    if (AUTH_CONFIG.isBackend) return backendAuthService.signUp(input);
    if (AUTH_CONFIG.isMock) return mockAuthService.signUp(input);
    return notImplemented(AUTH_CONFIG.provider);
  },

  async signIn(input: SignInInput & { turnstileToken?: string }): Promise<AuthResult> {
    if (AUTH_CONFIG.isBackend) return backendAuthService.signIn(input);
    if (AUTH_CONFIG.isMock) return mockAuthService.signIn(input);
    return notImplemented(AUTH_CONFIG.provider);
  },

  async signOut(): Promise<void> {
    if (AUTH_CONFIG.isBackend) return backendAuthService.signOut();
    if (AUTH_CONFIG.isMock) return mockAuthService.signOut();
    return notImplemented(AUTH_CONFIG.provider);
  },

  async getSession() {
    if (AUTH_CONFIG.isBackend) return backendAuthService.getSession();
    if (AUTH_CONFIG.isMock) return mockAuthService.getSession();
    return null;
  },

  async forgotPassword(email: string) {
    if (AUTH_CONFIG.isBackend) return backendAuthService.forgotPassword(email);
    if (AUTH_CONFIG.isMock) return mockAuthService.forgotPassword(email);
    return notImplemented(AUTH_CONFIG.provider);
  },

  async resetPassword(token: string, newPassword: string) {
    if (AUTH_CONFIG.isBackend) return backendAuthService.resetPassword(token, newPassword);
    if (AUTH_CONFIG.isMock) return mockAuthService.resetPassword(token, newPassword);
    return notImplemented(AUTH_CONFIG.provider);
  },

  /**
   * Real Google Identity Services integration. Loads Google's own script,
   * opens the real One Tap / popup flow, and receives a signed ID token
   * from Google. That raw credential is then sent to OUR backend, which
   * verifies it server-side against Google's public keys (see
   * backend/app/core/security.py::verify_google_credential) before
   * creating a session — the browser-decoded profile is never trusted
   * directly, only used for the mock/offline path.
   */
  async signInWithGoogle(): Promise<AuthResult> {
    if (!AUTH_CONFIG.google.isConfigured) {
      throw new Error("Google Sign-In isn't configured. Set VITE_GOOGLE_CLIENT_ID in your .env file to enable it.");
    }
    const credentialResponse = await runGoogleIdentityFlow(AUTH_CONFIG.google.clientId);

    if (AUTH_CONFIG.isBackend) {
      return backendAuthService.signInWithGoogleCredential(credentialResponse.credential);
    }
    if (AUTH_CONFIG.isMock) {
      const profile = decodeGoogleCredential(credentialResponse.credential);
      return mockAuthService.signInWithGoogleProfile(profile);
    }
    return notImplemented(AUTH_CONFIG.provider);
  },
};

// ---- Google Identity Services helpers --------------------------------

let googleScriptPromise: Promise<void> | null = null;

function loadGoogleScript(): Promise<void> {
  if (googleScriptPromise) return googleScriptPromise;
  googleScriptPromise = new Promise((resolve, reject) => {
    if (document.getElementById("google-identity-services")) return resolve();
    const script = document.createElement("script");
    script.id = "google-identity-services";
    script.src = "https://accounts.google.com/gsi/client";
    script.async = true;
    script.defer = true;
    script.onload = () => resolve();
    script.onerror = () => reject(new Error("Failed to load Google Sign-In. Check your network connection."));
    document.head.appendChild(script);
  });
  return googleScriptPromise;
}

function decodeGoogleCredential(credential: string): { name: string; email: string; picture?: string } {
  const payload = credential.split(".")[1];
  const json = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
  const data = JSON.parse(decodeURIComponent(escape(json)));
  return { name: data.name ?? data.email, email: data.email, picture: data.picture };
}

function runGoogleIdentityFlow(clientId: string): Promise<{ credential: string }> {
  return new Promise((resolve, reject) => {
    loadGoogleScript()
      .then(() => {
        const google = (window as any).google;
        if (!google?.accounts?.id) {
          reject(new Error("Google Sign-In failed to initialize."));
          return;
        }
        google.accounts.id.initialize({
          client_id: clientId,
          callback: (response: { credential: string }) => resolve(response),
        });
        google.accounts.id.prompt((notification: any) => {
          if (notification.isNotDisplayed?.() || notification.isSkippedMoment?.()) {
            reject(new Error("Google Sign-In was closed before completing."));
          }
        });
      })
      .catch(reject);
  });
}
