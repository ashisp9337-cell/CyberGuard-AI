"""Email (SMTP) login check for CYBERGUARD. Run from backend/:  python smtp_check.py
Uses backend/.env. Never prints your password or username in full."""
import base64, smtplib, string, unicodedata
from app.core.config import get_settings

s = get_settings()
raw_pw = s.SMTP_PASSWORD
pw = raw_pw.replace(" ", "")
user = s.SMTP_USER

def describe(label, value):
    odd = [f"{unicodedata.name(ch, hex(ord(ch)))}" for ch in value if not (ch in string.ascii_letters + string.digits + "@._-+")]
    print(f"{label}: length {len(value)}, "
          f"{'all lowercase a-z' if value.isalpha() and value.islower() and value.isascii() else 'NOT only lowercase a-z'}"
          + (f", unusual characters: {odd}" if odd else ", no unusual characters"))

print(f"Host {s.SMTP_HOST}  port {s.SMTP_PORT}")
describe("Username", user)
print(f"Username looks like a Gmail address: {user.strip().lower().endswith('@gmail.com') and user == user.strip()}")
describe("Password (spaces removed)", pw)
print(f"Password had normal spaces: {raw_pw.count(' ')}, other space-like characters: "
      f"{sum(1 for ch in raw_pw if ch.isspace() and ch != ' ')}")

print("\n=== Login conversation with Gmail (port 465) - only Gmail's replies are shown ===")
try:
    c = smtplib.SMTP_SSL(s.SMTP_HOST, 465, timeout=20)
    code, msg = c.ehlo()
    auth_line = [l for l in msg.decode(errors="replace").splitlines() if l.upper().startswith("AUTH")]
    print("Gmail offers:", auth_line[0] if auth_line else "(no AUTH line)")
    for label, payload in (("AUTH LOGIN", None), ("username", user), ("password", pw)):
        if payload is None:
            c.putcmd("AUTH", "LOGIN")
        else:
            c.send((base64.b64encode(payload.encode("utf-8")).decode() + "\r\n").encode())
        code, reply = c.getreply()
        print(f"  after sending {label:10s} -> Gmail replied {code}: {reply.decode(errors='replace')[:160]}")
        if code >= 400:
            break
    else:
        print("  >>> LOGIN WORKS on port 465")
    try:
        c.quit()
    except Exception:
        pass
except Exception as e:
    print(f"  connection dropped -> {type(e).__name__}: {e}")
