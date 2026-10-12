"""
CyberGuard email doctor -- finds out WHY Gmail sending (SMTP) or reading (IMAP) fails.

Run from backend/ with the venv active:   python email_doctor.py
Reads backend/.env. Never prints a password, never sends an email, changes nothing.

Checks, in order:
  1. Can this PC reach Gmail's servers (DNS + ports 465, 587, 993)?
  2. Is something INTERCEPTING the secure connection? (who issued the certificate -- it must be Google;
     antivirus "mail shields" and some college/company networks put their own certificate in the middle)
  3. Gmail's exact answer to each login (sending account and reading account, both sending ports)
  4. Cross-test: the reading account's App Password on the SENDING server
"""
import base64
import imaplib
import smtplib
import socket
import ssl

from app.core.config import get_settings

s = get_settings()
TIMEOUT = 15


def mask(email: str) -> str:
    if "@" not in email:
        return f"<not an email address, {len(email)} characters>"
    name, dom = email.split("@", 1)
    return f"{name[:3]}***@{dom}"


def clean(pw: str) -> str:
    return (pw or "").replace(" ", "").replace(" ", "").strip()


def line(t=""):
    print(t, flush=True)


def cert_issuer(host: str, port: int, starttls: bool = False) -> str:
    ctx = ssl.create_default_context()
    try:
        if starttls:
            c = smtplib.SMTP(host, port, timeout=TIMEOUT)
            c.ehlo()
            c.starttls(context=ctx)
            cert = c.sock.getpeercert()
            c.close()
        else:
            with socket.create_connection((host, port), timeout=TIMEOUT) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as tls:
                    cert = tls.getpeercert()
        issuer = dict(x[0] for x in cert.get("issuer", []))
        return issuer.get("organizationName") or issuer.get("commonName") or "unknown"
    except ssl.SSLCertVerificationError as e:
        return f"NOT TRUSTED ({e.verify_message}) -- something is intercepting"
    except Exception as e:
        return f"could not check ({type(e).__name__}: {e})"


def smtp_login(user: str, pw: str, port: int) -> str:
    try:
        if port == 465:
            c = smtplib.SMTP_SSL(s.SMTP_HOST, 465, timeout=TIMEOUT, context=ssl.create_default_context())
        else:
            c = smtplib.SMTP(s.SMTP_HOST, port, timeout=TIMEOUT)
            c.ehlo()
            c.starttls(context=ssl.create_default_context())
        c.ehlo()
        try:
            c.login(user, pw)
            result = "OK - login accepted"
        except smtplib.SMTPAuthenticationError as e:
            msg = e.smtp_error.decode(errors="replace") if isinstance(e.smtp_error, bytes) else str(e.smtp_error)
            result = f"REFUSED by Gmail ({e.smtp_code}): {msg[:150]}"
        try:
            c.quit()
        except Exception:
            pass
        return result
    except smtplib.SMTPServerDisconnected as e:
        return f"CONNECTION DROPPED ({e}) -- the connection was cut, Gmail never answered the login"
    except Exception as e:
        return f"FAILED ({type(e).__name__}: {e})"


def imap_login(user: str, pw: str) -> str:
    try:
        c = imaplib.IMAP4_SSL(s.IMAP_HOST, 993, timeout=TIMEOUT)
        try:
            c.login(user, pw)
            result = "OK - login accepted"
        except imaplib.IMAP4.error as e:
            result = f"REFUSED by Gmail: {e}"
        try:
            c.logout()
        except Exception:
            pass
        return result
    except Exception as e:
        return f"FAILED ({type(e).__name__}: {e})"


smtp_user, smtp_pw = s.SMTP_USER.strip(), clean(s.SMTP_PASSWORD)
imap_user, imap_pw = (s.IMAP_USER or s.SMTP_USER).strip(), clean(s.IMAP_PASSWORD or s.SMTP_PASSWORD)

line("=== Settings (from backend/.env) ===")
line(f"Sending  : {s.SMTP_HOST}:{s.SMTP_PORT}  as {mask(smtp_user)}  password {len(smtp_pw)} letters")
line(f"Reading  : {s.IMAP_HOST}:993  as {mask(imap_user)}  password {len(imap_pw)} letters")
line(f"Alerts to: {mask(s.ALERT_EMAIL_TO)}")
for name, pw in (("Sending", smtp_pw), ("Reading", imap_pw)):
    if pw and (len(pw) != 16 or not pw.isalpha()):
        line(f"  ! {name} password is not 16 letters -- a Gmail App Password is exactly 16 letters")

line("\n=== 1. Can this PC reach Gmail? ===")
unreachable = []
for host, port in ((s.SMTP_HOST, 465), (s.SMTP_HOST, 587), (s.IMAP_HOST, 993)):
    try:
        ip = socket.gethostbyname(host)
        with socket.create_connection((host, port), timeout=TIMEOUT):
            line(f"  {host}:{port} -> reachable ({ip})")
    except Exception as e:
        unreachable.append(f"{host}:{port}")
        line(f"  {host}:{port} -> BLOCKED ({type(e).__name__}: {e})")

line("\n=== 2. Is the secure connection intercepted? (issuer must be Google) ===")
issuers = {
    "sending 465": cert_issuer(s.SMTP_HOST, 465),
    "sending 587": cert_issuer(s.SMTP_HOST, 587, starttls=True),
    "reading 993": cert_issuer(s.IMAP_HOST, 993),
}
def _intercepted(v: str) -> bool:
    return not v.startswith("could not check") and "google" not in v.lower()


for k, v in issuers.items():
    note = "(OK)" if "google" in v.lower() else "" if v.startswith("could not check") else \
        "<-- NOT Google: antivirus / network is in the middle"
    line(f"  {k}: issued by {v}  {note}")

line("\n=== 3. Gmail's answer to each login ===")
r_imap = imap_login(imap_user, imap_pw)
line(f"  Reading account {mask(imap_user)} on IMAP 993 : {r_imap}")
r465 = smtp_login(smtp_user, smtp_pw, 465)
r587 = smtp_login(smtp_user, smtp_pw, 587)
line(f"  Sending account {mask(smtp_user)} on SMTP 465 : {r465}")
line(f"  Sending account {mask(smtp_user)} on SMTP 587 : {r587}")

cross = None
if imap_user.lower() != smtp_user.lower() or imap_pw != smtp_pw:
    line("\n=== 4. Cross-test: reading account on the SENDING server ===")
    cross = smtp_login(imap_user, imap_pw, 587)
    line(f"  {mask(imap_user)} on SMTP 587 : {cross}")

line("\n=== DIAGNOSIS ===")
intercepted = [k for k, v in issuers.items() if _intercepted(v)]
if len(unreachable) == 3:
    line("This PC cannot reach Gmail at all (no internet, DNS problem, or a firewall blocking these ports).")
    line("Check the internet connection, then try a mobile hotspot.")
elif r465.startswith("OK") or r587.startswith("OK"):
    port = 465 if r465.startswith("OK") else 587
    line(f"Sending works on port {port}. Set SMTP_PORT={port} in .env, restart the backend, press 'Send test alert'.")
elif intercepted:
    line(f"Your connection to Gmail is intercepted on: {', '.join(intercepted)}.")
    line("Most likely an antivirus 'Email protection / Mail shield / SSL scanning' feature (Avast, AVG, Kaspersky,")
    line("Quick Heal, ESET, Bitdefender ...) or a college/office network filter. Turn that feature off, or test on")
    line("a mobile hotspot, then run this again.")
elif cross and cross.startswith("OK"):
    line(f"The network is fine and Gmail sending works with {mask(imap_user)}.")
    line(f"The problem is the OLD sending account {mask(smtp_user)} / its App Password.")
    line("FIX: in .env set SMTP_USER and SMTP_FROM to the reading account and SMTP_PASSWORD to its App Password")
    line("(the same 16 letters as IMAP_PASSWORD), SMTP_PORT=587, then restart the backend.")
elif "REFUSED" in r465 or "REFUSED" in r587:
    line("Gmail answered but refused the password. Create a NEW App Password for the sending account at")
    line("https://myaccount.google.com/apppasswords (2-Step Verification must be on) and put it in SMTP_PASSWORD.")
elif "DROPPED" in r465 and "DROPPED" in r587:
    line("Gmail's sending server cuts the connection before answering, while the certificate is Google's.")
    line("This happens when a firewall/antivirus/ISP blocks outgoing mail login. Try a mobile hotspot to confirm.")
else:
    line("Not clear yet -- send this whole output to your assistant.")
