// ---------------------------------------------------------------------------
// Mock authentication service — browser-only demo implementation.
//
// IMPORTANT: this is NOT production-grade authentication. Passwords are
// obfuscated with a simple non-cryptographic hash purely so nothing sits in
// localStorage in plaintext during the demo; there is no server, no
// transport security, and no real session token. Do not reuse this for a
// real product — replace it by implementing the same function signatures
// in `authService.ts` against Firebase Auth, Supabase Auth, Auth0, or a
// custom backend. No UI code should need to change when you do.
// ---------------------------------------------------------------------------

import type { AuthResult, AuthUser, SignInInput, SignUpInput } from "@/types";
import { fakeHash, generateId } from "@/lib/utils";

const USERS_KEY = "cyberguard.auth.users.v1";
const SESSION_KEY = "cyberguard.auth.session.v1";

interface StoredUser extends AuthUser {
  passwordHash: string;
}

function readUsers(): Record<string, StoredUser> {
  try {
    return JSON.parse(localStorage.getItem(USERS_KEY) ?? "{}");
  } catch {
    return {};
  }
}

function writeUsers(users: Record<string, StoredUser>) {
  localStorage.setItem(USERS_KEY, JSON.stringify(users));
}

function delay<T>(value: T, ms = 700): Promise<T> {
  return new Promise((resolve) => setTimeout(() => resolve(value), ms));
}

function toPublicUser(u: StoredUser): AuthUser {
  const { passwordHash: _passwordHash, ...pub } = u;
  return pub;
}

export const mockAuthService = {
  async signUp(input: SignUpInput): Promise<AuthResult> {
    const email = input.email.trim().toLowerCase();
    const users = readUsers();
    if (users[email]) {
      await delay(null, 500);
      throw new Error("An account with this email already exists.");
    }
    const user: StoredUser = {
      id: generateId("USR"),
      name: input.name.trim(),
      email,
      provider: "password",
      createdAt: new Date().toISOString(),
      passwordHash: fakeHash(input.password),
    };
    users[email] = user;
    writeUsers(users);
    localStorage.setItem(SESSION_KEY, JSON.stringify({ userId: user.id }));
    return delay({ user: toPublicUser(user) });
  },

  async signIn(input: SignInInput): Promise<AuthResult> {
    const email = input.email.trim().toLowerCase();
    const users = readUsers();
    const user = users[email];
    if (!user || user.passwordHash !== fakeHash(input.password)) {
      await delay(null, 600);
      throw new Error("Incorrect email or password.");
    }
    localStorage.setItem(SESSION_KEY, JSON.stringify({ userId: user.id }));
    return delay({ user: toPublicUser(user) });
  },

  async signInWithGoogleProfile(profile: { name: string; email: string; picture?: string }): Promise<AuthResult> {
    const email = profile.email.trim().toLowerCase();
    const users = readUsers();
    let user = users[email];
    if (!user) {
      user = {
        id: generateId("USR"),
        name: profile.name,
        email,
        avatarUrl: profile.picture,
        provider: "google",
        createdAt: new Date().toISOString(),
        passwordHash: "",
      };
      users[email] = user;
      writeUsers(users);
    }
    localStorage.setItem(SESSION_KEY, JSON.stringify({ userId: user.id }));
    return delay({ user: toPublicUser(user) }, 200);
  },

  async signOut(): Promise<void> {
    localStorage.removeItem(SESSION_KEY);
    return delay(undefined, 200);
  },

  getSession(): AuthUser | null {
    try {
      const raw = localStorage.getItem(SESSION_KEY);
      if (!raw) return null;
      const { userId } = JSON.parse(raw);
      const users = readUsers();
      const match = Object.values(users).find((u) => u.id === userId);
      return match ? toPublicUser(match) : null;
    } catch {
      return null;
    }
  },

  /**
   * Always resolves the same way regardless of whether the email exists,
   * so the UI never reveals which addresses have accounts. The "reset
   * token" here is just a base64 of the email for demo purposes — a real
   * backend would email a signed, single-use, expiring link instead.
   */
  async forgotPassword(email: string): Promise<{ devResetToken?: string }> {
    const normalized = email.trim().toLowerCase();
    const users = readUsers();
    const exists = Boolean(users[normalized]);
    await delay(null, 700);
    return { devResetToken: exists ? btoa(normalized) : undefined };
  },

  async resetPassword(token: string, newPassword: string): Promise<void> {
    let email: string;
    try {
      email = atob(token);
    } catch {
      throw new Error("This reset link is invalid or has expired.");
    }
    const users = readUsers();
    const user = users[email];
    if (!user) {
      await delay(null, 500);
      throw new Error("This reset link is invalid or has expired.");
    }
    user.passwordHash = fakeHash(newPassword);
    writeUsers(users);
    return delay(undefined, 600);
  },
};
