"""
One-time setup: creates all CodeLedger tables in your Aiven database
and loads the sample data.

Run:  python import_db.py
Uses the same settings as the app (.env file or environment variables).
"""
import re
import sys
from dotenv import load_dotenv
load_dotenv()
import engine


def read_sql(path):
    text = open(path, encoding="utf-8").read()
    # Aiven's database is called "defaultdb", so remove the lines that
    # would create/switch to a database called "codeledger".
    text = re.sub(r"(?im)^\s*CREATE DATABASE[^;]*;\s*$", "", text)
    text = re.sub(r"(?im)^\s*USE\s+[^;]*;\s*$", "", text)
    return text


def split_statements(sql):
    """Split on ';' but ignore ';' inside quotes and comments."""
    stmts, buf = [], []
    quote = None
    i, n = 0, len(sql)
    while i < n:
        c = sql[i]
        if quote:
            buf.append(c)
            if c == "\\" and i + 1 < n:
                buf.append(sql[i + 1]); i += 1
            elif c == quote:
                if i + 1 < n and sql[i + 1] == quote:   # '' escaped quote
                    buf.append(sql[i + 1]); i += 1
                else:
                    quote = None
        elif c in ("'", '"', "`"):
            quote = c; buf.append(c)
        elif sql.startswith("--", i):
            j = sql.find("\n", i)
            i = n if j == -1 else j
            continue
        elif c == ";":
            s = "".join(buf).strip()
            if s:
                stmts.append(s)
            buf = []
        else:
            buf.append(c)
        i += 1
    s = "".join(buf).strip()
    if s:
        stmts.append(s)
    return stmts


def run_file(conn, path):
    statements = split_statements(read_sql(path))
    print(f"\n{path}: {len(statements)} statements")
    with conn.cursor() as cur:
        for k, s in enumerate(statements, 1):
            try:
                cur.execute(s)
            except Exception as e:
                print(f"  [FAIL] statement {k}: {s[:80]!r}...\n         {e}")
                conn.rollback()
                raise SystemExit(1)
    conn.commit()
    print("  [OK] done")


if __name__ == "__main__":
    cfg = engine._mysql_settings()
    print(f"Connecting to {cfg['host']}:{cfg['port']} database={cfg['database']} ...")
    conn = engine.get_mysql_connection()
    print("[OK] Connected")

    run_file(conn, "schema.sql")

    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) AS n FROM ecosystems")
        already = cur.fetchone()["n"] > 0
    if already:
        print("\nseed.sql skipped: data already exists (this is fine).")
    else:
        run_file(conn, "seed.sql")

    with conn.cursor() as cur:
        cur.execute("SHOW TABLES")
        tables = [list(r.values())[0] for r in cur.fetchall()]
    print("\nTables now in database:", tables)
    conn.close()
    print("\nALL DONE. Reload your website.")
