"""Email (SMTP) step-by-step check for CYBERGUARD. Run from backend/:  python smtp_check.py
Uses the settings in backend/.env. Never prints your password."""
import smtplib, socket, ssl, traceback
from app.core.config import get_settings

s = get_settings()
pw = s.SMTP_PASSWORD.replace(" ", "")
print(f"Host {s.SMTP_HOST}  port {s.SMTP_PORT}  user {s.SMTP_USER[:2]}***  password length {len(pw)} (should be 16)")

def step(name, fn):
    try:
        out = fn()
        print(f"  OK    {name}" + (f"  -> {str(out)[:90]}" if out else ""))
        return True
    except Exception as e:
        print(f"  FAIL  {name}  -> {type(e).__name__}: {e}")
        return False

for port in (465, 587):
    print(f"\n=== Port {port} ===")
    try:
        if port == 465:
            box = {}
            if not step("connect with SSL", lambda: box.setdefault("c", smtplib.SMTP_SSL(s.SMTP_HOST, 465, timeout=20)).sock.version()):
                continue
            c = box["c"]
        else:
            box = {}
            if not step("connect", lambda: box.setdefault("c", smtplib.SMTP(s.SMTP_HOST, 587, timeout=20)) and None):
                continue
            c = box["c"]
            if not step("hello (EHLO)", lambda: c.ehlo()[0]):
                continue
            if not step("start encryption (STARTTLS)", lambda: c.starttls()[0]):
                continue
        step("hello (EHLO)", lambda: c.ehlo()[0])
        if step("login", lambda: c.login(s.SMTP_USER, pw)[0]):
            print(f"  >>> Port {port} WORKS. Put SMTP_PORT={port} in backend/.env")
        try:
            c.quit()
        except Exception:
            pass
    except Exception:
        traceback.print_exc()
