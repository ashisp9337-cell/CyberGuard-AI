import { useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/Button";
import { ICONS } from "@/lib/icons";
import type { OtpChallenge } from "@/services/auth/otpAuthService";

interface OtpStepProps {
  challenge: OtpChallenge;
  verifyLabel: string;
  onVerify: (code: string) => Promise<void>;
  onResend: () => Promise<OtpChallenge>;
  onBack: () => void;
}

/** "Enter the 6-digit code we emailed you" — with a resend countdown. */
export function OtpStep({ challenge, verifyLabel, onVerify, onResend, onBack }: OtpStepProps) {
  const [current, setCurrent] = useState(challenge);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [wait, setWait] = useState(challenge.resendInSeconds);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => inputRef.current?.focus(), []);
  useEffect(() => {
    if (wait <= 0) return;
    const t = setTimeout(() => setWait((w) => w - 1), 1000);
    return () => clearTimeout(t);
  }, [wait]);

  async function submit(e?: React.FormEvent) {
    e?.preventDefault();
    setError(null);
    if (code.length !== 6) {
      setError("Enter the 6-digit code.");
      return;
    }
    setBusy(true);
    try {
      await onVerify(code);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Verification failed.");
      setCode("");
      inputRef.current?.focus();
    } finally {
      setBusy(false);
    }
  }

  async function resend() {
    setError(null);
    setInfo(null);
    try {
      const next = await onResend();
      setCurrent(next);
      setWait(next.resendInSeconds);
      setCode("");
      setInfo("A new code has been sent.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not send a new code.");
    }
  }

  return (
    <form onSubmit={submit} noValidate className="space-y-4">
      <div className="rounded-lg border border-cyan-500/25 bg-cyan-500/5 px-3 py-2.5 text-sm text-slate-300 flex gap-2">
        <ICONS.email size={16} className="text-cyan-400 shrink-0 mt-0.5" />
        <span>
          We sent a 6-digit code to <span className="text-white font-medium">{current.sentTo}</span>. It expires in{" "}
          {Math.round(current.expiresInSeconds / 60)} minutes.
        </span>
      </div>

      {current.devOtp && (
        <div className="rounded-lg border border-amber-500/25 bg-amber-500/5 p-3 text-left">
          <p className="text-[11px] font-semibold text-amber-400 uppercase tracking-wide mb-1">Development mode</p>
          <p className="text-xs text-slate-400">
            {current.deliveryNote ?? "Email is not set up."} Your code is{" "}
            <span className="font-mono text-amber-300 text-sm">{current.devOtp}</span>
          </p>
        </div>
      )}

      <div>
        <label htmlFor="otp" className="block text-sm font-medium text-white mb-1.5">Verification code</label>
        <input
          id="otp"
          ref={inputRef}
          inputMode="numeric"
          autoComplete="one-time-code"
          maxLength={6}
          value={code}
          onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
          placeholder="••••••"
          className="w-full rounded-lg bg-elevated border border-strong px-3 py-3 text-center text-2xl tracking-[0.6em] font-mono text-white focus-ring"
        />
      </div>

      {error && (
        <p className="text-xs text-red-400 flex items-center gap-1.5" role="alert">
          <ICONS.warning size={13} /> {error}
        </p>
      )}
      {info && !error && <p className="text-xs text-emerald-400">{info}</p>}

      <Button type="submit" size="lg" className="w-full" disabled={busy || code.length !== 6}>
        {busy ? <ICONS.loader size={16} className="animate-spin" /> : <ICONS.shieldCheck size={16} />}
        {busy ? "Verifying..." : verifyLabel}
      </Button>

      <div className="flex items-center justify-between text-xs">
        <button type="button" onClick={onBack} className="text-slate-400 hover:text-white focus-ring rounded">
          ← Back
        </button>
        <button
          type="button"
          onClick={resend}
          disabled={wait > 0}
          className="text-cyan-400 hover:text-cyan-300 disabled:text-slate-500 focus-ring rounded"
        >
          {wait > 0 ? `Resend code in ${wait}s` : "Resend code"}
        </button>
      </div>
    </form>
  );
}
