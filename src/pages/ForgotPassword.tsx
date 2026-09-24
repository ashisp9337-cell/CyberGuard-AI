import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { AuthLayout } from "@/components/auth/AuthLayout";
import { AuthCard } from "@/components/auth/AuthCard";
import { TextInput } from "@/components/ui/Input";
import { Button } from "@/components/ui/Button";
import { useAuth } from "@/context/AuthContext";
import { ICONS } from "@/lib/icons";

export default function ForgotPassword() {
  const { forgotPassword } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [sent, setSent] = useState(false);
  const [devResetToken, setDevResetToken] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!email.trim()) return;
    setSubmitting(true);
    try {
      const { devResetToken: token } = await forgotPassword(email.trim());
      setDevResetToken(token ?? null);
      setSent(true);
    } finally {
      setSubmitting(false);
    }
  }

  if (sent) {
    return (
      <AuthLayout>
        <div className="text-center">
          <div className="h-12 w-12 rounded-xl bg-cyan-500/10 flex items-center justify-center mx-auto mb-5">
            <ICONS.email size={22} className="text-cyan-400" />
          </div>
          <h1 className="text-xl font-bold text-white">Check Your Email</h1>
          <p className="text-sm text-slate-400 mt-2 leading-relaxed">
            If an account exists for <span className="text-slate-300">{email}</span>, password reset instructions will be sent.
          </p>

          {devResetToken && (
            <div className="mt-5 rounded-lg border border-amber-500/25 bg-amber-500/5 p-3 text-left">
              <p className="text-[11px] font-semibold text-amber-400 uppercase tracking-wide mb-1.5">Development mode</p>
              <p className="text-xs text-slate-400 leading-relaxed mb-2">
                No email service is connected in this prototype. Use this link to continue the demo flow:
              </p>
              <Link
                to={`/reset-password?token=${devResetToken}`}
                className="text-xs font-mono text-cyan-400 hover:text-cyan-300 break-all focus-ring rounded"
              >
                /reset-password?token={devResetToken}
              </Link>
            </div>
          )}

          <Button variant="secondary" className="mt-6 w-full" onClick={() => navigate("/signin")}>
            Return to Sign In
          </Button>
        </div>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout>
      <AuthCard
        title="Reset Your Password"
        subtitle="Enter your email address and we'll send you instructions to reset your password."
        footer={
          <p className="text-center text-sm text-slate-400">
            Remembered it?{" "}
            <Link to="/signin" className="text-cyan-400 hover:text-cyan-300 font-medium focus-ring rounded">
              Sign In
            </Link>
          </p>
        }
      >
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
          <Button type="submit" size="lg" className="w-full" disabled={submitting}>
            {submitting ? <ICONS.loader size={16} className="animate-spin" /> : null}
            {submitting ? "Sending..." : "Send Reset Instructions"}
          </Button>
        </form>
      </AuthCard>
    </AuthLayout>
  );
}
