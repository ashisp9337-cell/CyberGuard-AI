r"""Score a folder of YOUR OWN recordings with the voice models - the honest real-world check.

    python -m app.ml.training.check_voice_samples C:\path\to\folder --expect real
    python -m app.ml.training.check_voice_samples C:\path\to\folder --expect fake

--expect real : genuine recordings (e.g. your WhatsApp voice notes, Hindi / Odia speech) -> counts false alarms
--expect fake : AI voices you made yourself (e.g. a clone of YOUR OWN voice, with your consent) -> counts catches
Only reads the files; prints one line per recording and a summary. Nothing is uploaded or saved.
"""
import argparse
import os
import sys
import time

AUDIO = (".ogg", ".opus", ".m4a", ".mp3", ".wav", ".aac", ".flac", ".webm")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("folder")
    ap.add_argument("--expect", choices=("real", "fake"), required=True)
    ap.add_argument("--no-speech", action="store_true", help="skip speech-to-text (faster)")
    a = ap.parse_args()
    from app.detectors import voice, voice_audio as V
    sess, meta = voice.ai_model()
    if sess is None:
        sys.exit(f"The AI-voice model is not ready: {meta}")
    lv = meta["levels"]
    files = sorted(os.path.join(a.folder, f) for f in os.listdir(a.folder) if f.lower().endswith(AUDIO))
    if not files:
        sys.exit(f"No audio files ({', '.join(AUDIO)}) in {a.folder}")
    print(f"alert level {lv['alert']:.3f}, check-carefully level {lv['verify']:.3f}; {len(files)} file(s)\n")
    at_alert = at_verify = judged = 0
    for p in files:
        t = time.time()
        try:
            x = V.speech(p)
        except ValueError as e:
            print(f"  unreadable  {os.path.basename(p)}: {e}")
            continue
        clips = V.clips(x)
        if not clips:
            print(f"  too short   {os.path.basename(p)} ({x.size / V.SR:.1f} s of speech)")
            continue
        s = voice.ai_voice_score(clips)["score"]
        judged += 1
        at_alert += s >= lv["alert"]
        at_verify += s >= lv["verify"]
        tag = "ALERT " if s >= lv["alert"] else "verify" if s >= lv["verify"] else "  -   "
        lang = ""
        if not a.no_speech:
            tr = voice.transcribe(x)
            lang = f"  [{tr.get('language')}] {tr.get('text', '')[:60]!r}" if tr else ""
        print(f"  {tag} {s:.3f}  {os.path.basename(p)[:40]:40s} {x.size / V.SR:5.1f}s {time.time() - t:4.1f}s{lang}")
    if judged:
        word = "false alarms" if a.expect == "real" else "caught"
        print(f"\n{judged} recordings judged: {word} at alert {at_alert} ({at_alert / judged:.0%}), "
              f"at check-carefully {at_verify} ({at_verify / judged:.0%})")


if __name__ == "__main__":
    main()
