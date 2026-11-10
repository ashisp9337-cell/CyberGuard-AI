// (11 Nov) Voice & Audio result: every check in plain words + a timeline of the AI-voice model's score for each
// 4-second part of the speech. Only numbers and short texts come from the server - never the audio itself.
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { ICONS } from "@/lib/icons";
import type { VoiceAnalysisInfo } from "@/types";

type Tone = "bad" | "warn" | "ok" | "info";
const TONE: Record<Tone, string> = {
  bad: "border-red-500/40 bg-red-500/5 text-red-300",
  warn: "border-amber-500/40 bg-amber-500/5 text-amber-300",
  ok: "border-emerald-500/30 bg-emerald-500/5 text-emerald-300",
  info: "border-slate-500/30 bg-slate-500/5 text-slate-300",
};
const ICON: Record<Tone, string> = { bad: "✖", warn: "⚠", ok: "✔", info: "•" };

function Check({ tone, title, text }: { tone: Tone; title: string; text: string }) {
  return (
    <li className={`rounded-md border p-2.5 ${TONE[tone]}`}>
      <p className="text-sm font-medium">{ICON[tone]} {title}</p>
      <p className="text-xs text-slate-400 mt-0.5">{text}</p>
    </li>
  );
}

const LANG: Record<string, string> = { en: "English", hi: "Hindi", or: "Odia", bn: "Bengali", ta: "Tamil", te: "Telugu",
  mr: "Marathi", gu: "Gujarati", kn: "Kannada", ml: "Malayalam", pa: "Punjabi", ur: "Urdu" };
const pct = (v: number | null | undefined) => (v == null ? "-" : `${Math.round(v * 100)}%`);

export function VoiceCard({ va }: { va: VoiceAnalysisInfo }) {
  const ai = va.aiVoice;
  const clips = (ai?.clipScores ?? []).filter((c): c is number => typeof c === "number");
  const alert = ai?.alert ?? null;
  const verify = ai?.verify ?? null;
  const step = va.clipSeconds ?? 4;
  const level = (v: number) => (alert != null && v >= alert ? "bad" : verify != null && v >= verify ? "warn" : "ok");
  const hot = clips.filter((c) => level(c) === "bad").length;
  const checks: { tone: Tone; title: string; text: string }[] = [];

  if (va.aigcLabel?.label) {
    const proof = va.aigcLabel.label === "1";
    checks.push({ tone: proof ? "bad" : "warn", title: proof ? "AI label in the file: made by AI" : "AI label in the file: possibly AI",
      text: `The file carries the official AI-content (AIGC) label${va.aigcLabel.producer ? ` written by ${va.aigcLabel.producer}` : ""}. `
        + (proof ? "The tool that made it declared it AI-generated - this is proof, whatever it sounds like." : "The tool was not sure - check carefully.") });
  }
  if (va.contentCredentials === "ai") {
    checks.push({ tone: "bad", title: "Content Credentials: made with AI", text: "The file's C2PA record says an AI tool made it - proof." });
  } else if (va.contentCredentials === "present") {
    checks.push({ tone: "info", title: "Content Credentials present", text: "Signed by an app, without an AI declaration. Check them at contentcredentials.org/verify." });
  }
  if (ai && ai.score != null) {
    const lv = level(ai.score);
    checks.push({ tone: lv === "bad" && va.modelOnlyCapped ? "warn" : lv,
      title: lv === "bad" ? (va.modelOnlyCapped ? "Voice model: sounds AI - check carefully" : "Voice model: sounds AI-generated")
        : lv === "warn" ? "Voice model: possibly AI - check carefully" : "Voice model: no sign of an AI voice",
      text: `Average ${pct(ai.score)} over ${va.clipsScored} part(s) (check from ${pct(verify)}, alert from ${pct(alert)}).`
        + (va.modelOnlyCapped ? " Nothing else points to a fake, so this alone is 'check carefully': phone recordings with noise suppression can sound synthetic to it." : "")
        + (lv === "ok" ? " This does not prove the voice is real - new voice cloners can pass." : "") });
  } else if (va.aiVoiceUnavailable) {
    checks.push({ tone: "info", title: "Voice model not installed", text: va.aiVoiceUnavailable });
  }
  if (va.speech) {
    const s = va.speech.contentScore;
    checks.push({ tone: s != null && s >= 51 ? "bad" : "ok",
      title: s != null && s >= 51 ? "The words sound like a scam" : "The words do not sound like a scam",
      text: `${va.speech.language ? `Spoken in ${LANG[va.speech.language] ?? va.speech.language}. ` : ""}"${va.speech.transcriptExcerpt}"` });
  }
  if (va.voiceMatch?.done) {
    checks.push({ tone: va.voiceMatch.match ? "info" : "bad",
      title: va.voiceMatch.match ? "Voice matches the genuine recording" : "Voice does NOT match the genuine recording",
      text: `Similarity ${va.voiceMatch.similarity?.toFixed(2) ?? "-"} (level ${va.voiceMatch.mismatchLevel?.toFixed(2) ?? "-"}).`
        + (va.voiceMatch.match ? " A good clone is made to match, so this alone proves nothing." : " Probably not the person it claims to be.") });
  }

  return (
    <Card>
      <CardHeader title="Voice check" icon={<ICONS.audio size={16} />}
        subtitle={`${va.speechSeconds != null ? `${va.speechSeconds.toFixed(1)} s of speech` : "Speech"} · ${va.clipsScored} part(s) of ${step} s judged · the audio is not stored`} />
      <CardBody className="space-y-4">
        {checks.length > 0 && <ul className="space-y-2">{checks.map((c) => <Check key={c.title} {...c} />)}</ul>}

        {clips.length > 0 && (
          <div>
            <p className="text-[11px] uppercase tracking-wide text-slate-500 mb-1">AI-voice score for each {step}-second part of the speech</p>
            <div className="relative h-28 rounded-md border border-default bg-elevated/30 px-2 pt-2" role="img"
              aria-label={`Voice model score per part: ${clips.map((c) => pct(c)).join(", ")}`}>
              {[{ v: alert, c: "border-red-400/70", t: "alert" }, { v: verify, c: "border-amber-400/70", t: "check" }].map((l) => l.v != null && (
                <div key={l.t} className={`absolute left-0 right-0 border-t border-dashed ${l.c}`} style={{ bottom: `${l.v * 100}%` }}>
                  <span className="absolute right-1 -top-4 text-[10px] text-slate-500">{l.t} {pct(l.v)}</span>
                </div>
              ))}
              <div className="flex h-full items-end gap-1">
                {clips.map((c, i) => (
                  <div key={i} className="flex-1 h-full flex items-end" title={`${i * step}-${(i + 1) * step} s: ${pct(c)}`}>
                    <div className={`w-full rounded-t ${level(c) === "bad" ? "bg-red-500/70" : level(c) === "warn" ? "bg-amber-500/70" : "bg-emerald-500/60"}`}
                      style={{ height: `${Math.max(c * 100, 2)}%` }} />
                  </div>
                ))}
              </div>
            </div>
            <div className="flex gap-1 px-2 mt-1">
              {clips.map((_, i) => <span key={i} className="flex-1 text-center text-[10px] text-slate-500">{i * step}s</span>)}
            </div>
            <p className="text-[11px] text-slate-500 mt-1">
              Red = typical of an AI voice, amber = check, green = no sign. {hot > 0 && hot < clips.length
                ? `Only ${hot} of ${clips.length} parts are red: part of the recording may be AI - or that part is noisy or music.`
                : hot === clips.length ? "Every part is red: the whole recording sounds AI-made to the model." : "No part reached the alert level."}
              {" "}Times count speech only (pauses are skipped).
            </p>
          </div>
        )}

        <div className="rounded-md border border-cyan-500/20 bg-cyan-500/5 p-2.5">
          <p className="text-xs font-medium text-cyan-200">What to do with any voice note asking for money, an OTP or secrecy</p>
          <p className="text-xs text-slate-400 mt-0.5">Hang up and call the person back on a number you already have, or ask a question only the real person knows. Never pay or share an OTP because of a voice alone.</p>
        </div>
      </CardBody>
    </Card>
  );
}
