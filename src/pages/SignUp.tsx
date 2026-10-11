import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { AuthLayout } from "@/components/auth/AuthLayout";
import { AuthCard } from "@/components/auth/AuthCard";
import { AuthDivider } from "@/components/auth/AuthDivider";
import { GoogleSignInButton } from "@/components/auth/GoogleSignInButton";
import { PasswordInput } from "@/components/auth/PasswordInput";
import { PasswordStrength, passwordMeetsRequirements } from "@/components/auth/PasswordStrength";
import { Captcha } from "@/components/auth/Captcha";
import { OtpStep } from "@/components/auth/OtpStep";
import { TextInput } from "@/components/ui/Input";
import { Button } from "@/components/ui/Button";
import { useAuth } from "@/context/AuthContext";
import { AUTH_CONFIG } from "@/services/auth/config";
import { otpAuthService, type OtpChallenge } from "@/services/auth/otpAuthService";
import { ICONS } from "@/lib/icons";

type Step = "details" | "otp" | "password";

const STEPS: { key: Step; label: string }[] = [
  { key: "details", label: "Your details" },
  { key: "otp", label: "Verify email" },
  { key: "password", label: "Create password" },
];

function StepIndicator({ step }: { step: Step }) {
  const at = STEPS.findIndex((s) => s.key === step);
  return (
    <ol className="flex items-center gap-2 mb-5 text-[11px]">
      {STEPS.map((s, i) => (
        <li key={s.key} className="flex items-center gap-2 flex-1">
          <span
            className={`h-5 w-5 rounded-full flex items-center justify-center font-semibold shrink-0 ${
              i < at ? "bg-emerald-500 text-slate-950" : i === at ? "bg-cyan-500 text-slate-950" : "bg-elevated text-slate-500 border border-strong"
            }`}
          >
            {i < at ? "✓" : i + 1}
          </span>
          <span className={i === at ? "text-white font-medium" : "text-slate-500"}>{s.label}</span>
        </li>
      ))}
    </ol>
  );
}

export default function SignUp() {
  const { signUp, acceptSignedInUser } = useAuth();
  const navigate = useNavigate();

  const [step, setStep] = useState<Step>("details");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [captchaVerified, setCaptchaVerified] = useState(false);
  const [turnstileToken, setTurnstileToken] = useState<string | null>(null);
  const [challenge, setChallenge] = useState<OtpChallenge | null>(null);
  const [signupToken, setSignupToken] = useState<string | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  // ---- Step 1: name + email -> code is emailed --------------------------------
  async function handleDetails(e: React.FormEvent) {
    e.preventDefault();
    setFormError(null);
    const next: Record<string, string> = {};
    if (!name.trim()) next.name = "Please enter your full name.";
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) next.email = "Please enter a valid email address.";
    setErrors(next);
    if (Object.keys(next).length) return;
    if (!captchaVerified) {
      setFormError("Please complete the verification step below.");
      return;
    }
    if (!AUTH_CONFIG.isBackend) {
      setStep("password"); // offline demo mode has no email step
      return;
    }
    setSubmitting(true);
    try {
      setChallenge(await otpAuthService.startSignup(name.trim(), email.trim(), turnstileToken ?? undefined));
      setStep("otp");
    } catch (err) {
      setFormError(err instanceof Error ? err.message : "Could not send the verification code. Please try again.");
    } finally {
      setSubmitting(false);
    }
  }

  // ---- Step 3: create password -> account is created and signed in ------------
  async function handlePassword(e: React.FormEvent) {
    e.preventDefault();
    setFormError(null);
    const next: Record<string, string> = {};
    if (!passwordMeetsRequirements(password)) next.password = "Password doesn't meet the requirements below.";
    if (confirmPassword !== password) next.confirmPassword = "Passwords do not match.";
    setErrors(next);
    if (Object.keys(next).length) return;
    setSubmitting(true);
    try {
      if (AUTH_CONFIG.isBackend && signupToken) {
        acceptSignedInUser(await otpAuthService.completeSignup(signupToken, password));
      } else {
        await signUp({ name: name.trim(), email: email.trim(), password, turnstileToken: turnstileToken ?? undefined });
      }
      navigate("/dashboard", { replace: true });
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Could not create your account. Please try again.";
      setFormError(msg);
      if (/expired|start the sign-up again/i.test(msg)) {
        setSignupToken(null);
        setStep("details");
      }
    } finally {
      setSubmitting(false);
    }
  }

  const footer = (
    <p className="text-center text-sm text-slate-400">
      Already have an account?{" "}
      <Link to="/signin" className="text-cyan-400 hover:text-cyan-300 font-medium focus-ring rounded">
        Sign In
      </Link>
    </p>
  );

  return (
    <AuthLayout>
      <AuthCard
        title={step === "details" ? "Create Your Security Workspace" : step === "otp" ? "Verify Your Email" : "Create Your Password"}
        subtitle={
          step === "details"
            ? "We'll email you a code to confirm the address is yours."
            : step === "otp"
            ? "Enter the 6-digit code from your inbox."
            : `Email verified. Choose a strong password for ${email.trim()}.`
        }
        footer={footer}
      >
        <StepIndicator step={step} />

        {step === "details" && (
          <>
            <GoogleSignInButton label="Continue with Google" onError={setFormError} />
            <AuthDivider />
            <form onSubmit={handleDetails} noValidate className="space-y-4">
              <TextInput label="Full Name" required autoComplete="name" value={name}
                onChange={(e) => setName(e.target.value)} placeholder="Jane Doe" error={errors.name} />
              <TextInput label="Email Address" type="email" required autoComplete="email" value={email}
                onChange={(e) => setEmail(e.target.value)} placeholder="you@company.com" error={errors.email} />
              <Captcha onVerify={setCaptchaVerified} onToken={setTurnstileToken} />
              {formError && (
                <p className="text-xs text-red-400 flex items-center gap-1.5" role="alert">
                  <ICONS.warning size={13} /> {formError}
                </p>
              )}
              <Button type="submit" size="lg" className="w-full" disabled={submitting || !captchaVerified}>
                {submitting ? <ICONS.loader size={16} className="animate-spin" /> : <ICONS.email size={16} />}
                {submitting ? "Sending code..." : "Send Verification Code"}
              </Button>
            </form>
          </>
        )}

        {step === "otp" && challenge && (
          <OtpStep
            challenge={challenge}
            verifyLabel="Verify Email"
            onVerify={async (code) => {
              const res = await otpAuthService.verifySignup(challenge.challengeId, code);
              setSignupToken(res.signupToken);
              setFormError(null);
              setStep("password");
            }}
            onResend={() => otpAuthService.resend(challenge.challengeId, "signup")}
            onBack={() => setStep("details")}
          />
        )}

        {step === "password" && (
          <form onSubmit={handlePassword} noValidate className="space-y-4">
            <p className="text-xs text-emerald-400 flex items-center gap-1.5 rounded-lg border border-emerald-500/25 bg-emerald-500/5 px-3 py-2.5">
              <ICONS.success size={13} /> {email.trim()} is verified.
            </p>
            <div>
              <PasswordInput label="Password" required autoComplete="new-password" value={password}
                onChange={(e) => setPassword(e.target.value)} placeholder="Create a strong password" error={errors.password} />
              <PasswordStrength password={password} />
            </div>
            <PasswordInput label="Confirm Password" required autoComplete="new-password" value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)} placeholder="Re-enter your password" error={errors.confirmPassword} />
            {formError && (
              <p className="text-xs text-red-400 flex items-center gap-1.5" role="alert">
                <ICONS.warning size={13} /> {formError}
              </p>
            )}
            <Button type="submit" size="lg" className="w-full" disabled={submitting}>
              {submitting ? <ICONS.loader size={16} className="animate-spin" /> : <ICONS.shieldCheck size={16} />}
              {submitting ? "Creating account..." : "Create Account"}
            </Button>
            <p className="text-[11px] text-slate-500 text-center leading-relaxed">
              By creating an account, you agree to the Terms of Service and Privacy Policy.
            </p>
          </form>
        )}
      </AuthCard>
    </AuthLayout>
  );
}
