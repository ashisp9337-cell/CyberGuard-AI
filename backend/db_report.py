"""
CyberGuard database report -- READ-ONLY. Run from backend/ with the venv active:   python db_report.py

Confirms the database connection (from DATABASE_URL in backend/.env) and lists every table with
how many rows it holds, its size, and the newest entry. Never prints the database password and
never changes anything (it only runs SELECT queries).
"""
import re

from sqlalchemy import create_engine, inspect, text

from app.core.config import get_settings

url = get_settings().DATABASE_URL
print("Database:", re.sub(r"://([^:/@]+):[^@]*@", r"://\1:****@", url))

engine = create_engine(url)
try:
    with engine.connect() as conn:
        if url.startswith("postgres"):
            print("Connected  :", conn.execute(text("select version()")).scalar().split(",")[0])
            print("DB name    :", conn.execute(text("select current_database()")).scalar())
            print("Total size :", conn.execute(text("select pg_size_pretty(pg_database_size(current_database()))")).scalar())
        else:
            print("Connected  : SQLite")
        try:
            print("Migration  :", conn.execute(text("select version_num from alembic_version")).scalar(),
                  "(latest is e5a1c9d7f3b2)")
        except Exception:
            print("Migration  : (no alembic_version table)")

        tables = sorted(inspect(conn).get_table_names())
        print(f"\n{'table':24s} {'rows':>8s} {'size':>10s}  newest entry")
        print("-" * 70)
        for t in tables:
            rows = conn.execute(text(f'select count(*) from "{t}"')).scalar()
            size = ""
            if url.startswith("postgres"):
                size = conn.execute(text("select pg_size_pretty(pg_total_relation_size(:t))"), {"t": t}).scalar()
            cols = {c["name"] for c in inspect(conn).get_columns(t)}
            newest = ""
            for c in ("created_at", "timestamp", "last_seen", "updated_at", "sent_at"):
                if c in cols and rows:
                    newest = str(conn.execute(text(f'select max("{c}") from "{t}"')).scalar())[:19]
                    break
            print(f"{t:24s} {rows:>8d} {size:>10s}  {newest}")
except Exception as e:
    print("\nNOT CONNECTED:", type(e).__name__, "-", str(e).splitlines()[0][:200])
    print("Check that PostgreSQL is running and DATABASE_URL in backend/.env is correct.")
