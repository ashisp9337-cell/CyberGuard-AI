"""Move everything from one CyberGuard account to another email address.

Use this when an account was made with an email you can't reach any more.
Run it from the backend folder, with the venv active:

    python move_account.py --list                                   # see accounts and their data
    python move_account.py --from old@example.com --to you@gmail.com        # preview only, changes nothing
    python move_account.py --from old@example.com --to you@gmail.com --yes  # really do it

Two cases, chosen automatically:
  * The new email has NO account yet: the old account simply gets the new email.
    Same password and all data stay; the next sign-in code goes to the new email.
  * The new email ALREADY has an account: every scan, report, incident, contact, IOC,
    email record and log is moved into it, then the old, now-empty account is deleted.
    The new account keeps its own password and settings.

Everything happens in one database transaction: if anything fails, nothing changes.
"""
import argparse
import sys

from app.db.database import SessionLocal
from app.db import models as m

# Every table that belongs to a user (rows tied to a scan follow the scan automatically).
OWNED = [m.Scan, m.ThreatEvent, m.Report, m.KnownContact, m.EmailRecord, m.LoginEvent, m.AuditLog]


def _count(db, user_id):
    out = {t.__tablename__: db.query(t).filter(t.user_id == user_id).count() for t in OWNED}
    out["iocs"] = db.query(m.IOC).filter(m.IOC.user_id == user_id).count()
    out["sender_history"] = db.query(m.SenderHistory).filter(m.SenderHistory.user_id == user_id).count()
    return out


def _show(label, db, user):
    counts = _count(db, user.id)
    nice = ", ".join(f"{k} {v}" for k, v in counts.items() if v)
    print(f"  {label}{user.email}  (name: {user.name}, created {user.created_at:%Y-%m-%d})")
    print(f"      data: {nice or 'none'}")


def _find(db, email):
    return db.query(m.User).filter(m.User.email == email.strip().lower()).first()


def list_accounts(db):
    users = db.query(m.User).order_by(m.User.created_at).all()
    if not users:
        print("No accounts in this database.")
    for u in users:
        _show("", db, u)


def _merge_into(db, old, new):
    """Move every row from old to new, merging the few things that must stay unique."""
    for t in OWNED:
        db.query(t).filter(t.user_id == old.id).update({t.user_id: new.id}, synchronize_session=False)

    # IOCs: one row per (type, value) per user, so merge duplicates instead of copying them.
    for ioc in db.query(m.IOC).filter(m.IOC.user_id == old.id).all():
        same = db.query(m.IOC).filter(m.IOC.user_id == new.id, m.IOC.ioc_type == ioc.ioc_type,
                                      m.IOC.value == ioc.value).first()
        if same:
            same.times_seen = (same.times_seen or 0) + (ioc.times_seen or 0)
            same.max_risk = max(same.max_risk or 0, ioc.max_risk or 0)
            same.modules = sorted(set(same.modules or []) | set(ioc.modules or []))
            same.first_seen = min(same.first_seen, ioc.first_seen)
            if ioc.last_seen > same.last_seen:
                same.last_seen, same.last_scan_id = ioc.last_seen, ioc.last_scan_id
            db.delete(ioc)
        else:
            ioc.user_id = new.id

    # Sender memory: one row per sender address, so add the counts together.
    for snd in db.query(m.SenderHistory).filter(m.SenderHistory.user_id == old.id).all():
        same = db.query(m.SenderHistory).filter(m.SenderHistory.user_id == new.id,
                                                m.SenderHistory.sender_address == snd.sender_address).first()
        if same:
            same.message_count += snd.message_count
            same.safe_count += snd.safe_count
            same.malicious_count += snd.malicious_count
            same.first_seen = min(same.first_seen, snd.first_seen)
            same.last_seen = max(same.last_seen, snd.last_seen)
            db.delete(snd)
        else:
            snd.user_id = new.id

    # Settings: keep the new account's own settings if it has them, otherwise take the old ones.
    old_settings = db.query(m.UserSettings).filter(m.UserSettings.user_id == old.id).first()
    if old_settings:
        if db.query(m.UserSettings).filter(m.UserSettings.user_id == new.id).first():
            db.delete(old_settings)
        else:
            old_settings.user_id = new.id

    if (old.role or "").lower() == "admin":
        new.role = "admin"

    # Old sign-in codes and reset links point at the unreachable email: remove them, then the account.
    db.query(m.EmailOTP).filter((m.EmailOTP.user_id == old.id) | (m.EmailOTP.email == old.email)).delete(synchronize_session=False)
    db.query(m.PasswordResetToken).filter(m.PasswordResetToken.user_id == old.id).delete(synchronize_session=False)
    db.flush()
    db.expire_all()
    db.delete(db.get(m.User, old.id))


def main():
    p = argparse.ArgumentParser(description="Move a CyberGuard account's data to another email.")
    p.add_argument("--list", action="store_true", help="show all accounts and how much data each has")
    p.add_argument("--from", dest="src", help="the old email (the one you can't reach)")
    p.add_argument("--to", dest="dst", help="your real email")
    p.add_argument("--yes", action="store_true", help="really make the change (without it: preview only)")
    a = p.parse_args()

    db = SessionLocal()
    try:
        if a.list or not (a.src and a.dst):
            list_accounts(db)
            if not a.list:
                print("\nThen run:  python move_account.py --from OLD_EMAIL --to REAL_EMAIL")
            return 0

        src, dst = a.src.strip().lower(), a.dst.strip().lower()
        if src == dst:
            print("The two emails are the same. Nothing to do.")
            return 1
        if "@" not in dst or "." not in dst.split("@")[-1]:
            print(f"'{a.dst}' doesn't look like an email address.")
            return 1
        old = _find(db, src)
        if not old:
            print(f"No account with the email {src}. Run 'python move_account.py --list' to see them.")
            return 1
        new = _find(db, dst)

        print("Moving FROM:")
        _show("", db, old)
        if new:
            print("Moving INTO the existing account:")
            _show("", db, new)
            print("\nPlan: move all data above into the second account, then delete the empty first account.")
            print("      Sign in afterwards with the SECOND account's password.")
        else:
            print(f"\nPlan: {dst} has no account yet, so the account above just gets this new email.")
            print("      Same password, same data. The next sign-in code goes to the new email.")

        if not a.yes:
            print("\nPREVIEW ONLY - nothing was changed. Add --yes to the same command to do it.")
            return 0

        if new:
            _merge_into(db, old, new)
            target = new
        else:
            db.query(m.EmailOTP).filter(m.EmailOTP.email == old.email).delete(synchronize_session=False)
            db.query(m.PasswordResetToken).filter(m.PasswordResetToken.user_id == old.id).delete(synchronize_session=False)
            old.email = dst
            old.provider = "password" if old.password_hash else old.provider
            target = old
        target.session_version = int(target.session_version or 0) + 1      # every old login cookie ends
        db.add(m.AuditLog(user_id=target.id, actor="admin-script", action="account.moved",
                          target=dst, detail={"from": src, "merged": bool(new)}))
        db.commit()
        db.refresh(target)
        print("\nDONE. The account now looks like this:")
        _show("", db, target)
        print(f"\nSign in at the website with {dst}. The 6-digit code will arrive at that email.")
        return 0
    except Exception as e:
        db.rollback()
        print(f"\nSomething went wrong, so NOTHING was changed: {type(e).__name__}: {e}")
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
