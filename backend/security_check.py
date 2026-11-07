"""
CyberGuard security self-check (6 Nov 2026). Run from the backend folder:

    venv\\Scripts\\activate
    python security_check.py

It reads backend/.env, the frontend's .env (project folder), Git and the database, and prints PASS / WARN / FAIL
lines with setting NAMES only - it never prints a password, key, token or e-mail address, so the output is safe to
show or screenshot. Nothing is changed.
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
results = []


def out(level: str, what: str, fix: str = "") -> None:
    results.append(level)
    print(f"[{level}] {what}" + (f"\n        -> {fix}" if fix else ""))


def read_env(path: str) -> dict:
    """KEY=VALUE pairs of a .env file (values stay in memory, they are never printed)."""
    values = {}
    try:
        with open(path, encoding="utf-8-sig") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                values[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        return {}
    return values


WEAK_PASSWORDS = {"", "postgres", "password", "admin", "root", "123456", "12345678", "changeme", "cyberguard",
                  "cyberguard_dev_password", "secret", "test", "pass", "qwerty"}
SECRET_NAMES = ("JWT_SECRET", "GEMINI_API_KEY", "TELEGRAM_BOT_TOKEN", "SMTP_PASSWORD", "IMAP_PASSWORD",
                "URLSCAN_API_KEY", "VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "TWILIO_AUTH_TOKEN", "CALLMEBOT_APIKEY",
                "TURNSTILE_SECRET_KEY", "GOOGLE_SAFE_BROWSING_API_KEY")


def check_backend_env() -> None:
    path = os.path.join(HERE, ".env")
    env = read_env(path)
    if not env:
        out("FAIL", "backend/.env is missing or empty", "copy .env.example .env, then fill it in")
        return
    from app.core.config import Settings, security_problems
    s = Settings()
    for p in security_problems(s):
        out("FAIL" if s.is_production or "JWT_SECRET" in p else "WARN", p)
    if len(s.JWT_SECRET) >= 64:
        out("PASS", "JWT_SECRET is long and random-looking (64+ characters)")
    out("PASS" if not s.DEBUG else "WARN", f"DEBUG is {'off' if not s.DEBUG else 'ON (shows internal errors)'}")
    out("PASS" if not s.EXPOSE_DEV_CODES else "FAIL", "EXPOSE_DEV_CODES is " + ("off" if not s.EXPOSE_DEV_CODES else
        "ON: login codes are returned to whoever asks"), "" if not s.EXPOSE_DEV_CODES else "set EXPOSE_DEV_CODES=false")
    out("PASS" if not s.ENABLE_API_DOCS else "WARN", "API documentation pages are " +
        ("off" if not s.ENABLE_API_DOCS else "ON (/docs shows every route)"), "" if not s.ENABLE_API_DOCS else
        "set ENABLE_API_DOCS=false for the demo")
    out("PASS", f"ENVIRONMENT = {s.ENVIRONMENT}" + (" (set production + COOKIE_SECURE=true when it runs on a real "
                                                   "HTTPS website)" if not s.is_production else ""))
    db = env.get("DATABASE_URL", "")
    m = re.match(r"^[a-z0-9+]+://([^:/@]*)(?::([^@]*))?@([^/:?]+)", db)
    if not db:
        out("FAIL", "DATABASE_URL is not set")
    elif m:
        user, pw, host = m.group(1), m.group(2) or "", m.group(3)
        if pw.lower() in WEAK_PASSWORDS or len(pw) < 10:
            out("WARN", "the database password is empty, short or a common one",
                "in pgAdmin: ALTER USER <your user> PASSWORD '<long random password>'; then update DATABASE_URL")
        else:
            out("PASS", "the database password is not a common / short one")
        if user.lower() == "postgres":
            out("WARN", "the app connects as the PostgreSQL superuser 'postgres'",
                "make a separate user that owns only the cyberguard database and use it in DATABASE_URL")
        if host not in ("localhost", "127.0.0.1", "::1") and "sslmode=" not in db:
            out("WARN", "the database is on another computer but the connection is not encrypted",
                "add ?sslmode=require to DATABASE_URL")
    present = [k for k in SECRET_NAMES if env.get(k)]
    out("PASS", f"{len(present)} secret setting(s) are kept in backend/.env (not in code): " + ", ".join(present))
    if not s.ADMIN_EMAILS.strip():
        out("WARN", "ADMIN_EMAILS is empty: the FIRST account ever created is the administrator",
            "set ADMIN_EMAILS=<your e-mail> so nobody else can become admin")
    else:
        out("PASS", "ADMIN_EMAILS names the administrator(s)")


def check_frontend_env() -> None:
    for name in (".env", ".env.local", ".env.production", ".env.production.local"):
        env = read_env(os.path.join(ROOT, name))
        if not env:
            continue
        exposed = [k for k in env if k.startswith("VITE_") and env[k]
                   and re.search(r"SECRET|PASSWORD|PRIVATE|TOKEN|API_KEY|APIKEY", k)
                   and not k.endswith(("SITE_KEY", "CLIENT_ID"))]
        if exposed:
            out("FAIL", f"{name}: {', '.join(exposed)} - every VITE_ value is sent to EVERY visitor's browser",
                "move the secret to backend/.env and let the backend use it")
        else:
            out("PASS", f"{name}: no secret in a VITE_ setting (VITE_ values are public by design)")
        if env.get("VITE_USE_MOCK_DATA", "").lower() == "true" or env.get("VITE_AUTH_PROVIDER", "") == "mock":
            out("WARN", f"{name}: demo mode is on for development (mock data / mock login)",
                "production builds ignore it, but switch it off to test the real login")


def check_git() -> None:
    def git(*args):
        try:
            return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            return None
    r = git("ls-files")
    if r is None or r.returncode != 0:
        out("WARN", "Git not found - skipped the Git checks")
        return
    tracked = r.stdout.split("\n")
    bad = [f for f in tracked if re.search(r"(^|/)\.env($|\.(?!example$)[^/]*$)|kaggle\.json$|\.pem$|\.key$|id_rsa"
                                           r"|automation_state\.json$|\.db$", f)]
    if bad:
        out("FAIL", f"{len(bad)} secret / private file(s) are tracked by Git: " + ", ".join(bad[:5]),
            "git rm --cached <file>, commit, and CHANGE every key that was in it (it is in the history)")
    else:
        out("PASS", "no .env, key, database or state file is tracked by Git")
    for f in ("backend/.env", ".env"):
        ig = git("check-ignore", "-q", f)
        if ig is not None and ig.returncode != 0:
            out("FAIL", f"{f} is NOT ignored by .gitignore", f"add {f} to .gitignore")
    hist = git("log", "--all", "--pretty=format:", "--name-only", "--diff-filter=A")
    if hist is not None:
        leaked = sorted({f for f in hist.stdout.split("\n") if re.search(r"(^|/)\.env$|kaggle\.json$|\.pem$", f)})
        if leaked:
            out("FAIL", "these were committed at some time (still in the history): " + ", ".join(leaked),
                "change every key that was in them; then remove them from the history")
        else:
            out("PASS", "no .env / key file was ever committed (whole history)")


def check_database() -> None:
    try:
        from app.db.database import SessionLocal
        from app.db.models import User
        db = SessionLocal()
        try:
            users = db.query(User).order_by(User.created_at.asc()).all()
            weak_hash = [u for u in users if u.password_hash and not u.password_hash.startswith(("$2b$", "$2a$", "$2y$"))]
            out("PASS" if not weak_hash else "FAIL", f"{len(users)} account(s); passwords stored as bcrypt hashes: "
                f"{len(users) - len(weak_hash)}", "" if not weak_hash else "those accounts must reset their password")
            demo = [u for u in users if u.email == "demo@cyberguard.local"]
            if demo:
                first = users and users[0].email == "demo@cyberguard.local"
                out("FAIL", "the demo account (published password DemoPass123) exists" +
                    (" and is the FIRST account = administrator" if first else ""),
                    "delete it in pgAdmin (users table) or change its password, before anyone else can use it")
            else:
                out("PASS", "no demo account with the published password")
        finally:
            db.close()
    except Exception as exc:  # noqa: BLE001
        out("WARN", f"could not open the database ({type(exc).__name__}) - start PostgreSQL and run again")


if __name__ == "__main__":
    print("CyberGuard security self-check - names only, no values are shown\n")
    for step in (check_backend_env, check_frontend_env, check_git, check_database):
        try:
            step()
        except Exception as exc:  # noqa: BLE001
            out("WARN", f"{step.__name__} could not finish ({type(exc).__name__})")
    print(f"\n{results.count('FAIL')} FAIL, {results.count('WARN')} WARN, {results.count('PASS')} PASS")
    sys.exit(1 if "FAIL" in results else 0)
