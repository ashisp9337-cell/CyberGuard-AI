import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { AuthLayout } from "@/components/auth/AuthLayout";
import { AuthCard } from "@/components/auth/AuthCard";
import { AuthDivider } from "@/components/auth/AuthDivider";
import { GoogleSignInButton } from "@/components/auth/GoogleSignInButton";
import { PasswordInput } from "@/components/auth/PasswordInput";
import { PasswordStrength, passwordMeetsRequirements } from "@/components/auth/PasswordStrength";
import { Captcha } from "@/components/auth/Captcha";
import { TextInput } from "@/components/ui/Input";
import { Button } from "@/components/ui/Button";
import { useAuth } from "@/context/AuthContext";
import { ICONS } from "@/lib/icons";

export default function SignUp() {
  const { signUp } = useAuth();
  const navigate = useNavigate();

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [captchaVerified, setCaptchaVerified] = useState(false);
  const [turnstileToken, setTurnstileToken] = useState<string | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  // Verification is always required — either the real Cloudflare Turnstile
  // widget (when configured) or the labeled development-mode checkbox.

  function validate(): boolean {
    const next: Record<string, string> = {};
    if (!name.trim()) next.name = "Please enter your full name.";
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) next.email = "Please enter a valid email address.";
    if (!passwordMeetsRequirements(password)) next.password = "Password doesn't meet the requirements below.";
    if (confirmPassword !== password) next.confirmPassword = "Passwords do not match.";
    setErrors(next);
    return Object.keys(next).length === 0;
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setFormError(null);
    if (!validate()) return;
    if (!captchaVerified) {
      setFormError("Please complete the verification step below.");
      return;
    }
    setSubmitting(true);
    try {
      await signUp({ name: name.trim(), email: email.trim(), password, turnstileToken: turnstileToken ?? undefined });
      navigate("/dashboard", { replace: true });
    } catch (err) {
      setFormError(err instanceof Error ? err.message : "Could not create your account. Please try again.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <AuthLayout>
      <AuthCard
        title="Create Your Security Workspace"
        subtitle="Start exploring CyberGuard's intelligent cybersecurity detection platform."
        footer={
          <p className="text-center text-sm text-slate-400">
            Already have an account?{" "}
            <Link to="/signin" className="text-cyan-400 hover:text-cyan-300 font-medium focus-ring rounded">
              Sign In
            </Link>
          </p>
        }
      >
        <GoogleSignInButton label="Continue with Google" onError={setFormError} />
        <AuthDivider />

        <form onSubmit={handleSubmit} noValidate className="space-y-4">
          <TextInput
            label="Full Name"
            required
            autoComplete="name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Jane Doe"
            error={errors.name}
          />
          <TextInput
            label="Email Address"
            type="email"
            required
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@company.com"
            error={errors.email}
          />
          <div>
            <PasswordInput
              label="Password"
              required
              autoComplete="new-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Create a strong password"
              error={errors.password}
            />
            <PasswordStrength password={password} />
          </div>
          <PasswordInput
            label="Confirm Password"
            required
            autoComplete="new-password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            placeholder="Re-enter your password"
            error={errors.confirmPassword}
          />

          <Captcha onVerify={setCaptchaVerified} onToken={setTurnstileToken} />

          {formError && (
            <p className="text-xs text-red-400 flex items-center gap-1.5" role="alert">
              <ICONS.warning size={13} /> {formError}
            </p>
          )}

          <Button type="submit" size="lg" className="w-full" disabled={submitting || !captchaVerified}>
            {submitting ? <ICONS.loader size={16} className="animate-spin" /> : null}
            {submitting ? "Creating account..." : "Create Account"}
          </Button>

          <p className="text-[11px] text-slate-500 text-center leading-relaxed">
            By creating an account, you agree to the Terms of Service and Privacy Policy.
          </p>
        </form>
      </AuthCard>
    </AuthLayout>
  );
}
