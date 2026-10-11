"""
One-time copy of the OLD SQLite data (backend/cyberguard.db) into PostgreSQL.

    python migrate_sqlite_to_postgres.py            # dry run: shows what WOULD be copied, changes nothing
    python migrate_sqlite_to_postgres.py --apply    # really copies it

Target = DATABASE_URL in backend/.env (must be PostgreSQL).

Safe to run more than once:
  * a row whose id is already in PostgreSQL is skipped (never overwritten);
  * a user whose EMAIL already exists in PostgreSQL is not duplicated -- that user's
    old scans/events/reports are attached to the existing PostgreSQL account instead;
  * everything is one transaction: if anything fails, nothing is written.
Expired password-reset tokens are not copied (they are useless after migration).
The SQLite file itself is never changed.
"""
import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sqlalchemy import Boolean, DateTime, Float, Integer, JSON, create_engine, select  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.core.config import get_settings  # noqa: E402
from app.db.models import (  # noqa: E402
    User, UserSettings, Scan, DetectedIndicatorRow, RecommendationRow, ThreatEvent, Report,
)

# Parents before children, so foreign keys always point at rows that exist.
ORDER = [
    ("users", User), ("settings", UserSettings), ("scans", Scan),
    ("detected_indicators", DetectedIndicatorRow), ("recommendations", RecommendationRow),
    ("threat_events", ThreatEvent), ("reports", Report),
]


def convert(value, coltype):
    """SQLite stores dates/JSON/booleans as text or numbers; turn them back into Python values."""
    if value is None:
        return None
    if isinstance(coltype, DateTime) and isinstance(value, str):
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    if isinstance(coltype, JSON) and isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return value
    if isinstance(coltype, Boolean):
        return bool(value)
    if isinstance(coltype, Integer) and not isinstance(value, bool):
        return int(value)
    if isinstance(coltype, Float):
        return float(value)
    return value


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sqlite", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "cyberguard.db"))
    ap.add_argument("--apply", action="store_true", help="really write (default is a dry run)")
    args = ap.parse_args()

    url = get_settings().DATABASE_URL
    if not url.startswith("postgresql"):
        sys.exit(f"DATABASE_URL in .env is not PostgreSQL ({url.split(':')[0]}). Nothing done.")
    if not os.path.exists(args.sqlite):
        sys.exit(f"SQLite file not found: {args.sqlite}")

    src = sqlite3.connect(args.sqlite)
    src.row_factory = sqlite3.Row
    src_tables = {r[0] for r in src.execute("select name from sqlite_master where type='table'")}

    engine = create_engine(url)
    user_map: dict[str, str] = {}      # old user id -> id to use in PostgreSQL
    new_scans: set[str] = set()        # scans copied in this run (their indicators/recommendations follow)
    summary = []

    with Session(engine) as db:
        for table, model in ORDER:
            if table not in src_tables:
                continue
            cols = {c.name: c for c in model.__table__.columns}
            rows = [dict(r) for r in src.execute(f'select * from "{table}"')]
            copied = skipped = merged = 0

            for row in rows:
                data = {k: convert(v, cols[k].type) for k, v in row.items() if k in cols}

                if table == "users":
                    if db.get(User, data["id"]):
                        user_map[data["id"]] = data["id"]; skipped += 1; continue
                    same_email = db.scalar(select(User).where(User.email == data["email"]))
                    if same_email:
                        user_map[data["id"]] = same_email.id; merged += 1; continue
                    user_map[data["id"]] = data["id"]
                else:
                    if db.get(model, data["id"]):
                        skipped += 1; continue
                    if "user_id" in data:
                        data["user_id"] = user_map.get(data["user_id"], data["user_id"])
                    if table == "settings" and db.scalar(
                            select(UserSettings).where(UserSettings.user_id == data["user_id"])):
                        skipped += 1; continue          # that account already has its own settings
                    if table in ("detected_indicators", "recommendations") and data.get("scan_id") not in new_scans:
                        skipped += 1; continue          # its scan was already in PostgreSQL
                    if table == "scans":
                        new_scans.add(data["id"])

                db.add(model(**data))
                db.flush()
                copied += 1
            summary.append((table, len(rows), copied, merged, skipped))

        print(f"\n{'table':22s}{'in SQLite':>10s}{'copied':>8s}{'merged':>8s}{'skipped':>9s}")
        for t, n, c, m, s in summary:
            print(f"{t:22s}{n:>10d}{c:>8d}{m:>8d}{s:>9d}")
        print("\nmerged  = user already existed in PostgreSQL (same email); their old data was attached to that account")
        print("skipped = already in PostgreSQL, or not needed\n")

        if args.apply:
            db.commit()
            print("DONE: data copied into PostgreSQL.")
        else:
            db.rollback()
            print("DRY RUN: nothing was written. Run again with --apply to copy for real.")


if __name__ == "__main__":
    main()
