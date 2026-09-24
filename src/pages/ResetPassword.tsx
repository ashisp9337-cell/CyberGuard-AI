import { useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { AuthLayout } from "@/components/auth/AuthLayout";
import { AuthCard } from "@/components/auth/AuthCard";
import { PasswordInput } from "@/components/auth/PasswordInput";
import { PasswordStrength, passwordMeetsRequirements } from "@/components/auth/PasswordStrength";
import { Button } from "@/components/ui/Button";
import { useAuth } from "@/context/AuthContext";
import { ICONS } from "@/lib/icons";

export default function ResetPassword() {
  const { resetPassword } = useAuth();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const token = searchParams.get("token") ?? "";

  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (!passwordMeetsRequirements(password)) {
      setError("Password doesn't meet the requirements below.");
      return;
    }
    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }
    if (!token) {
      setError("This reset link is invalid or has expired.");
      return;
    }
    setSubmitting(true);
    try {
      await resetPassword(token, password);
      navigate("/signin", { replace: true, state: { resetSuccess: true } });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not reset your password.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <AuthLayout>
      <AuthCard
        title="Set a New Password"
        subtitle="Choose a strong new password for your CyberGuard account."
        footer={
          <p className="text-center text-sm text-slate-400">
            <Link to="/signin" className="text-cyan-400 hover:text-cyan-300 font-medium focus-ring rounded">
              Back to Sign In
            </Link>
          </p>
        }
      >
        {!token && (
          <p className="text-xs text-red-400 flex items-center gap-1.5 mb-4" role="alert">
            <ICONS.warning size={13} /> This reset link is missing or invalid. Request a new one from the Forgot Password page.
          </p>
        )}

        <form onSubmit={handleSubmit} noValidate className="space-y-4">
          <div>
            <PasswordInput
              label="New Password"
              required
              autoComplete="new-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter a new password"
            />
            <PasswordStrength password={password} />
          </div>
          <PasswordInput
            label="Confirm New Password"
            required
            autoComplete="new-password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            placeholder="Re-enter your new password"
          />

          {error && (
            <p className="text-xs text-red-400 flex items-center gap-1.5" role="alert">
              <ICONS.warning size={13} /> {error}
            </p>
          )}

          <Button type="submit" size="lg" className="w-full" disabled={submitting}>
            {submitting ? <ICONS.loader size={16} className="animate-spin" /> : null}
            {submitting ? "Resetting..." : "Reset Password"}
          </Button>
        </form>
      </AuthCard>
    </AuthLayout>
  );
}
