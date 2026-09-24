import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import type { AuthUser, SignInInput, SignUpInput } from "@/types";
import { authService } from "@/services/auth/authService";

interface AuthContextValue {
  user: AuthUser | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  signUp: (input: SignUpInput & { turnstileToken?: string }) => Promise<void>;
  signIn: (input: SignInInput & { turnstileToken?: string }) => Promise<void>;
  signOut: () => Promise<void>;
  signInWithGoogle: () => Promise<void>;
  forgotPassword: (email: string) => Promise<{ devResetToken?: string }>;
  resetPassword: (token: string, newPassword: string) => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Restore any existing session (real backend cookie session, or demo
  // localStorage session in mock mode) on first load.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const session = await authService.getSession();
      if (!cancelled) {
        setUser(session);
        setIsLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  async function signUp(input: SignUpInput & { turnstileToken?: string }) {
    const { user: newUser } = await authService.signUp(input);
    setUser(newUser);
  }

  async function signIn(input: SignInInput & { turnstileToken?: string }) {
    const { user: signedInUser } = await authService.signIn(input);
    setUser(signedInUser);
  }

  async function signOut() {
    await authService.signOut();
    setUser(null);
  }

  async function signInWithGoogle() {
    const { user: googleUser } = await authService.signInWithGoogle();
    setUser(googleUser);
  }

  async function forgotPassword(email: string) {
    return authService.forgotPassword(email);
  }

  async function resetPassword(token: string, newPassword: string) {
    await authService.resetPassword(token, newPassword);
  }

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: Boolean(user),
        isLoading,
        signUp,
        signIn,
        signOut,
        signInWithGoogle,
        forgotPassword,
        resetPassword,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
