import { useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { AuthLayout } from "@/components/auth/AuthLayout";
import { AuthCard } from "@/components/auth/AuthCard";
import { AuthDivider } from "@/components/auth/AuthDivider";
import { GoogleSignInButton } from "@/components/auth/GoogleSignInButton";
import { PasswordInput } from "@/components/auth/PasswordInput";
import { TextInput } from "@/components/ui/Input";
import { Button } from "@/components/ui/Button";
import { useAuth } from "@/context/AuthContext";
import { ICONS } from "@/lib/icons";

export default function SignIn() {
  const { signIn } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const redirectTo = (location.state as { from?: string } | null)?.from ?? "/dashboard";
  const resetSuccess = Boolean((location.state as { resetSuccess?: boolean } | null)?.resetSuccess);

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [rememberMe, setRememberMe] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (!email.trim() || !password) {
      setError("Please enter your email and password.");
      return;
    }
    setSubmitting(true);
    try {
      await signIn({ email: email.trim(), password, rememberMe });
      navigate(redirectTo, { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign in failed. Please try again.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <AuthLayout>
      <AuthCard
        title="Welcome Back"
        subtitle="Sign in to access your CyberGuard security workspace."
        footer={
          <p className="text-center text-sm text-slate-400">
            Don't have an account?{" "}
            <Link to="/signup" className="text-cyan-400 hover:text-cyan-300 font-medium focus-ring rounded">
              Create one
            </Link>
          </p>
        }
      >
        <GoogleSignInButton label="Continue with Google" onError={setError} />
        <AuthDivider />

        {resetSuccess && (
          <p className="text-xs text-emerald-400 flex items-center gap-1.5 mb-4 rounded-lg border border-emerald-500/25 bg-emerald-500/5 px-3 py-2.5">
            <ICONS.success size={13} /> Your password has been reset. Sign in with your new password.
          </p>
        )}

        <form onSubmit={handleSubmit} noValidate className="space-y-4">
          <TextInput
            label="Email Address"
            type="email"
            required
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@company.com"
          />
          <PasswordInput
            label="Password"
            required
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter your password"
          />

          <div className="flex items-center justify-between">
            <label className="flex items-center gap-2 text-xs text-slate-400 cursor-pointer">
              <input
                type="checkbox"
                checked={rememberMe}
                onChange={(e) => setRememberMe(e.target.checked)}
                className="h-3.5 w-3.5 rounded border-strong bg-elevated accent-cyan-500 focus-ring"
              />
              Remember me
            </label>
            <Link to="/forgot-password" className="text-xs font-medium text-cyan-400 hover:text-cyan-300 focus-ring rounded">
              Forgot Password?
            </Link>
          </div>

          {error && (
            <p className="text-xs text-red-400 flex items-center gap-1.5" role="alert">
              <ICONS.warning size={13} /> {error}
            </p>
          )}

          <Button type="submit" size="lg" className="w-full" disabled={submitting}>
            {submitting ? <ICONS.loader size={16} className="animate-spin" /> : <ICONS.shieldCheck size={16} />}
            {submitting ? "Signing in..." : "Sign In Securely"}
          </Button>
        </form>
      </AuthCard>
    </AuthLayout>
  );
}
