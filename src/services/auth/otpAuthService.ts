// Email-OTP sign-up and login against the FastAPI backend.
//   Sign-up: startSignup(name, email) -> verifySignup(code) -> completeSignup(password)
//   Login:   startLogin(email, password) -> verifyLogin(code)
import type { AuthUser } from "@/types";
import { apiClient } from "@/services/api/client";

export interface OtpChallenge {
  challengeId: string;
  sentTo: string;              // masked email, e.g. as****@gmail.com
  delivered: boolean;          // false = email could not be sent (development mode shows devOtp)
  expiresInSeconds: number;
  resendInSeconds: number;
  devOtp?: string;             // DEVELOPMENT ONLY, when email is not working
  deliveryNote?: string;
}

function toUser(u: any): AuthUser {
  return { id: u.id, name: u.name, email: u.email, avatarUrl: u.avatarUrl ?? undefined, provider: u.provider, createdAt: u.createdAt };
}

export const otpAuthService = {
  startSignup(name: string, email: string, turnstileToken?: string) {
    return apiClient.post<OtpChallenge>("/api/auth/signup/start", { name, email, turnstileToken });
  },
  verifySignup(challengeId: string, code: string) {
    return apiClient.post<{ signupToken: string; email: string; name: string }>("/api/auth/signup/verify", { challengeId, code });
  },
  async completeSignup(signupToken: string, password: string): Promise<AuthUser> {
    const res = await apiClient.post<{ user: any }>("/api/auth/signup/complete", { signupToken, password });
    return toUser(res.user);
  },
  startLogin(email: string, password: string, rememberMe: boolean, turnstileToken?: string) {
    return apiClient.post<OtpChallenge & { otpRequired: true }>("/api/auth/login", { email, password, rememberMe, turnstileToken });
  },
  async verifyLogin(challengeId: string, code: string): Promise<AuthUser> {
    const res = await apiClient.post<{ user: any }>("/api/auth/login/verify", { challengeId, code });
    return toUser(res.user);
  },
  resend(challengeId: string, purpose: "signup" | "login") {
    return apiClient.post<OtpChallenge>("/api/auth/otp/resend", { challengeId, purpose });
  },
};
