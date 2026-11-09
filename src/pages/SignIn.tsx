import { useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { AuthLayout } from "@/components/auth/AuthLayout";
import { AuthCard } from "@/components/auth/AuthCard";
import { AuthDivider } from "@/components/auth/AuthDivider";
import { GoogleSignInButton, googleSignInEnabled } from "@/components/auth/GoogleSignInButton";
import { PasswordInput } from "@/components/auth/PasswordInput";
import { TextInput } from "@/components/ui/Input";
import { Button } from "@/components/ui/Button";
import { useAuth } from "@/context/AuthContext";
import { ICONS } from "@/lib/icons";
import { OtpStep } from "@/components/auth/OtpStep";
import { Captcha } from "@/components/auth/Captcha";
import { AUTH_CONFIG } from "@/services/auth/config";
import { otpAuthService, type OtpChallenge } from "@/services/auth/otpAuthService";

export default function SignIn() {
  const { signIn, acceptSignedInUser } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const redirectTo = (location.state as { from?: string } | null)?.from ?? "/dashboard";
  const resetSuccess = Boolean((location.state as { resetSuccess?: boolean } | null)?.resetSuccess);

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [rememberMe, setRememberMe] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  // Step 2 of login: the code emailed after the password was accepted.
  const [challenge, setChallenge] = useState<OtpChallenge | null>(null);
  // (9 Nov) Cloudflare Turnstile: the backend REQUIRES it for login in production (public website). Shown only when a
  // site key is configured; a token works once, so a failed try gets a fresh widget (captchaRound).
  const captchaOn = AUTH_CONFIG.isBackend && AUTH_CONFIG.turnstile.isConfigured;
  const [captchaVerified, setCaptchaVerified] = useState(false);
  const [turnstileToken, setTurnstileToken] = useState<string | null>(null);
  const [captchaRound, setCaptchaRound] = useState(0);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (!email.trim() || !password) {
      setError("Please enter your email and password.");
      return;
    }
    if (captchaOn && !captchaVerified) {
      setError("Please complete the verification step below.");
      return;
    }
    setSubmitting(true);
    try {
      if (AUTH_CONFIG.isBackend) {
        // Password is checked first; the session only starts after the emailed code.
        setChallenge(await otpAuthService.startLogin(email.trim(), password, rememberMe,
                                                     captchaOn ? turnstileToken ?? undefined : undefined));
      } else {
        await signIn({ email: email.trim(), password, rememberMe });
        navigate(redirectTo, { replace: true });
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign in failed. Please try again.");
      if (captchaOn) {                       // the used token cannot be sent again
        setCaptchaVerified(false);
        setTurnstileToken(null);
        setCaptchaRound((n) => n + 1);
      }
    } finally {
      setSubmitting(false);
    }
  }

  if (challenge) {
    return (
      <AuthLayout>
        <AuthCard title="Check Your Email" subtitle="One more step: enter the code we sent to confirm it's really you.">
          <OtpStep
            challenge={challenge}
            verifyLabel="Verify & Sign In"
            onVerify={async (code) => {
              acceptSignedInUser(await otpAuthService.verifyLogin(challenge.challengeId, code));
              navigate(redirectTo, { replace: true });
            }}
            onResend={() => otpAuthService.resend(challenge.challengeId, "login")}
            onBack={() => {
              setChallenge(null);
              setPassword("");
            }}
          />
        </AuthCard>
      </AuthLayout>
    );
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
        {googleSignInEnabled && (
          <>
            <GoogleSignInButton label="Continue with Google" onError={setError} />
            <AuthDivider />
          </>
        )}

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

          {captchaOn && (
            <Captcha key={captchaRound} onVerify={setCaptchaVerified} onToken={setTurnstileToken} />
          )}

          {error && (
            <p className="text-xs text-red-400 flex items-center gap-1.5" role="alert">
              <ICONS.warning size={13} /> {error}
            </p>
          )}

          <Button type="submit" size="lg" className="w-full" disabled={submitting || (captchaOn && !captchaVerified)}>
            {submitting ? <ICONS.loader size={16} className="animate-spin" /> : <ICONS.shieldCheck size={16} />}
            {submitting ? "Checking..." : "Continue"}
          </Button>
        </form>
      </AuthCard>
    </AuthLayout>
  );
}
