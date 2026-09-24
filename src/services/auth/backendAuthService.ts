// ---------------------------------------------------------------------------
// Real backend authentication — talks to the FastAPI CyberGuard API using
// HTTP-only session cookies (see src/services/api/client.ts). This is the
// production auth path; mockAuthService.ts remains available for
// offline/demo UI development via VITE_AUTH_PROVIDER=mock.
// ---------------------------------------------------------------------------
import type { AuthResult, AuthUser, SignInInput, SignUpInput } from "@/types";
import { apiClient, ApiError } from "@/services/api/client";

function fromBackendUser(u: any): AuthUser {
  return {
    id: u.id,
    name: u.name,
    email: u.email,
    avatarUrl: u.avatarUrl ?? undefined,
    provider: u.provider,
    createdAt: u.createdAt,
  };
}

export const backendAuthService = {
  async signUp(input: SignUpInput & { turnstileToken?: string }): Promise<AuthResult> {
    const res = await apiClient.post<{ user: any }>("/api/auth/register", input);
    return { user: fromBackendUser(res.user) };
  },

  async signIn(input: SignInInput & { turnstileToken?: string }): Promise<AuthResult> {
    const res = await apiClient.post<{ user: any }>("/api/auth/login", input);
    return { user: fromBackendUser(res.user) };
  },

  async signOut(): Promise<void> {
    await apiClient.post("/api/auth/logout");
  },

  async getSession(): Promise<AuthUser | null> {
    try {
      const user = await apiClient.get<any>("/api/auth/me");
      return fromBackendUser(user);
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) return null;
      return null;
    }
  },

  async forgotPassword(email: string): Promise<{ devResetToken?: string }> {
    const res = await apiClient.post<{ devResetToken?: string }>("/api/auth/forgot-password", { email });
    return res;
  },

  async resetPassword(token: string, newPassword: string): Promise<void> {
    await apiClient.post("/api/auth/reset-password", { token, newPassword });
  },

  async signInWithGoogleCredential(credential: string): Promise<AuthResult> {
    const res = await apiClient.post<{ user: any }>("/api/auth/google", { credential });
    return { user: fromBackendUser(res.user) };
  },
};
