#!/usr/bin/env python3
"""
Deploy the Bodyguard demo dataset to BigQuery — from the schema files.

The single source of truth is ``test/demo/detection-rules/schema/*.sql``: each
file holds one ``CREATE TABLE`` plus an ``INSERT`` with the most recent daily
window of sample rows. This script

1. runs those statements against ``<project>.<dataset>`` (tables are dropped
   and recreated, so the run is idempotent);
2. expands the three ``*_30d`` tables from one daily window to 30, with
   deterministic per-day jitter and a little realism (young phishing domains
   only exist from their registration day, DDoS bots burst, scanners come
   back every third day);
3. shifts every window so the most recent one is yesterday (UTC).

``--verify`` then runs every rule in ``test/demo/detection-rules/*.sql`` and
prints how many rows each one returns, so you know the demo queries are live.
``--check`` validates the schema files offline (column count vs. row arity)
without touching BigQuery.

Usage:
    python scripts/deploy_bq.py                      # deploy to the default project
    python scripts/deploy_bq.py --project my-proj    # your own project
    python scripts/deploy_bq.py --verify             # deploy, then run the rules
    python scripts/deploy_bq.py --check              # offline validation only

The dataset is created if missing. Credentials come from Application Default
Credentials (``gcloud auth application-default login``).
"""

from __future__ import annotations

import argparse
import datetime as dt
import re
import sys
from pathlib import Path

DEFAULT_PROJECT = "bodyguard-bh2026"
DEFAULT_DATASET = "bodyguard_demo"
DEFAULT_DAYS = 30

# Dataset name used *inside* the SQL files; rewritten to the target at deploy time.
SQL_DATASET = "bodyguard_demo"

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "test" / "demo" / "detection-rules"
SCHEMA_DIR = RULES_DIR / "schema"

# Tables that hold daily windows and get expanded; the rest (ip_reputation) are
# loaded as-is. Key = column that identifies an entity across windows.
WINDOWED = {"urls_30d": "url", "ip_30d": "client_ip", "domains_30d": "domain"}
# Load order matters: ip_30d / urls_30d look at the domains sample window while
# expanding, so domains_30d is expanded last.
EXPAND_ORDER = ["urls_30d", "ip_30d", "domains_30d"]


# ── SQL file parsing (pure functions, unit-tested) ─────────────────────────────

def split_statements(sql: str) -> list[str]:
    """Split on ';' at end of line. Comment-only fragments are dropped."""
    out = []
    for piece in re.split(r";[ \t]*\n", sql):
        body = re.sub(r"^\s*--.*$", "", piece, flags=re.M).strip()
        if body:
            out.append(piece.strip().rstrip(";") + ";")
    return out


_CREATE_RE = re.compile(r"CREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?\s+[`\"]?([\w.-]+)[`\"]?", re.I)


def table_name(create_stmt: str) -> str:
    m = _CREATE_RE.search(create_stmt)
    if not m:
        raise ValueError("not a CREATE TABLE statement")
    return m.group(1).split(".")[-1]


def column_names(create_stmt: str) -> list[str]:
    """Column names in declaration order (comments and PRIMARY KEY skipped)."""
    m = _CREATE_RE.search(create_stmt)
    if not m:
        raise ValueError("not a CREATE TABLE statement")
    start = create_stmt.index("(", m.end())   # the column list, not a '(' in the header comment
    end = create_stmt.rindex(")")
    cols = []
    for line in create_stmt[start + 1:end].splitlines():
        s = line.strip()
        if not s or s.startswith("--") or s.upper().startswith("PRIMARY KEY"):
            continue
        cols.append(s.split()[0].strip("`\""))
    return cols


def parse_values(insert_stmt: str) -> list[list[str]]:
    """Return the VALUES tuples of an INSERT as lists of raw tokens.

    Handles quoted strings (with '' escapes), -- comments outside strings,
    and nested parentheses inside a value (none expected, but harmless).
    """
    m = re.search(r"\bVALUES\b", insert_stmt, re.I)
    if not m:
        raise ValueError("no VALUES clause")
    text = insert_stmt[m.end():]
    rows: list[list[str]] = []
    row: list[str] = []
    tok: list[str] = []
    i, depth, in_str = 0, 0, False
    while i < len(text):
        c = text[i]
        if in_str:
            tok.append(c)
            if c == "'":
                if i + 1 < len(text) and text[i + 1] == "'":
                    tok.append("'")
                    i += 1
                else:
                    in_str = False
        elif c == "'":
            in_str = True
            tok.append(c)
        elif c == "-" and text.startswith("--", i):
            i = text.find("\n", i)
            if i < 0:
                break
        elif c == "(":
            depth += 1
            if depth > 1:
                tok.append(c)
        elif c == ")":
            depth -= 1
            if depth == 0:
                if "".join(tok).strip():
                    row.append("".join(tok).strip())
                rows.append(row)
                row, tok = [], []
            else:
                tok.append(c)
        elif c == "," and depth == 1:
            row.append("".join(tok).strip())
            tok = []
        elif depth >= 1:
            tok.append(c)
        i += 1
    return rows


def load_schema_file(path: Path) -> tuple[str, list[str], str, str]:
    """Return (table, columns, create_stmt, insert_stmt) after checking row arity."""
    stmts = split_statements(path.read_text(encoding="utf-8"))
    creates = [s for s in stmts if re.search(r"^\s*CREATE\s+TABLE", s, re.I | re.M)]
    inserts = [s for s in stmts if re.search(r"^\s*INSERT\s+INTO", s, re.I | re.M)]
    if len(creates) != 1 or len(inserts) != 1:
        raise ValueError(f"{path.name}: expected one CREATE TABLE and one INSERT, "
                         f"found {len(creates)} / {len(inserts)}")
    table = table_name(creates[0])
    cols = column_names(creates[0])
    rows = parse_values(inserts[0])
    for idx, r in enumerate(rows, 1):
        if len(r) != len(cols):
            raise ValueError(f"{path.name}: row {idx} has {len(r)} values, table has {len(cols)} columns "
                             f"(row starts {r[:3]})")
    return table, cols, creates[0], inserts[0]


def qualify(sql: str, project: str, dataset: str) -> str:
    """Rewrite `bodyguard_demo.table` references to the fully-qualified target."""
    return re.sub(rf"\b{SQL_DATASET}\.(\w+)", rf"`{project}.{dataset}.\1`", sql)


# ── Expansion SQL ──────────────────────────────────────────────────────────────

def jitter_expr(key: str) -> str:
    # Deterministic per (entity, day): the same deploy always yields the same rows.
    return f"0.75 + MOD(ABS(FARM_FINGERPRINT(CONCAT(CAST({key} AS STRING), '|', CAST(n AS STRING)))), 51) / 100"


def expansion_sql(table: str, cols: list[str], fqn: str, domains_fqn: str, sample_ts: str, days: int) -> str:
    """INSERT that adds days 1..days-1 for every sample row (day 0) of `table`."""
    key = WINDOWED[table]
    # Everything is read from alias x (the sample rows); d is only joined for the
    # domain age, so column names must be qualified to stay unambiguous.
    visits = "CAST(ROUND(x.visits * x.j) AS INT64)"
    blocked = f"LEAST({visits}, CAST(ROUND(x.blocked_count * x.j) AS INT64))"
    transforms = {
        "window_start": "TIMESTAMP_SUB(x.window_start, INTERVAL x.n DAY)",
        "window_end": "TIMESTAMP_SUB(x.window_end, INTERVAL x.n DAY)",
        "visits": visits,
        "blocked_count": blocked,
        "allowed_count": f"{visits} - {blocked}",
        "unique_ips": "GREATEST(1, CAST(ROUND(x.unique_ips * x.j) AS INT64))",
        "request_rate_per_h": "ROUND(x.request_rate_per_h * x.j, 1)",
        "domain_age_days": "x.domain_age_days - x.n",
    }
    select_list = ",\n    ".join(f"{transforms.get(c, 'x.' + c)} AS {c}" for c in cols)

    # Which days an entity is active. Young domains exist only since registration.
    if table == "domains_30d":
        join, active = "", "x.n <= x.domain_age_days"
    elif table == "urls_30d":
        join = f"LEFT JOIN {domains_fqn} d ON d.domain = x.host AND d.window_start = TIMESTAMP '{sample_ts}'"
        active = ("(d.domain IS NULL OR x.n <= d.domain_age_days)"
                  " AND (x.rule_id IS DISTINCT FROM 'CF_SCANNER_001' OR MOD(x.n, 3) = 0)")
    else:  # ip_30d
        join = f"LEFT JOIN {domains_fqn} d ON d.domain = x.top_host AND d.window_start = TIMESTAMP '{sample_ts}'"
        active = ("(d.domain IS NULL OR x.n <= d.domain_age_days)"
                  " AND (x.request_rate_per_h <= 1000 OR x.n IN (1, 15))"           # DDoS: bursts only
                  " AND (NOT REGEXP_CONTAINS(x.top_user_agent, r'(?i)nuclei|zgrab') OR MOD(x.n, 3) = 0)")  # scanners

    return f"""
INSERT INTO {fqn} ({", ".join(cols)})
SELECT
    {select_list}
FROM (
  SELECT b.*, n, {jitter_expr(key)} AS j
  FROM {fqn} b
  CROSS JOIN UNNEST(GENERATE_ARRAY(1, {days - 1})) AS n
  WHERE b.window_start = TIMESTAMP '{sample_ts}'
) x
{join}
WHERE {active}
""".strip()


def shift_sql(table: str, fqn: str, shift_days: int) -> str:
    if table in WINDOWED:
        return (f"UPDATE {fqn} SET window_start = TIMESTAMP_ADD(window_start, INTERVAL {shift_days} DAY), "
                f"window_end = TIMESTAMP_ADD(window_end, INTERVAL {shift_days} DAY) WHERE TRUE")
    return (f"UPDATE {fqn} SET first_seen = DATE_ADD(first_seen, INTERVAL {shift_days} DAY), "
            f"last_seen = DATE_ADD(last_seen, INTERVAL {shift_days} DAY) WHERE TRUE")


# ── Deploy ─────────────────────────────────────────────────────────────────────

def _client(project: str):
    sys.path.insert(0, str(REPO_ROOT))
    from agent.tls import use_system_trust_store  # corporate TLS interception, see agent/tls.py
    use_system_trust_store()
    from google.cloud import bigquery
    return bigquery, bigquery.Client(project=project)


def deploy(project: str, dataset: str, days: int, rebase: bool = True) -> None:
    bigquery, client = _client(project)
    ds_ref = f"{project}.{dataset}"
    client.create_dataset(bigquery.Dataset(ds_ref), exists_ok=True)
    print(f"Dataset {ds_ref} ready")

    schemas = {}
    for path in sorted(SCHEMA_DIR.glob("*.sql")):
        table, cols, create, insert = load_schema_file(path)
        schemas[table] = (cols, create, insert)

    def run(sql: str):
        return client.query(sql).result()

    def fqn(table: str) -> str:
        return f"`{ds_ref}.{table}`"

    for table, (cols, create, insert) in schemas.items():
        client.delete_table(f"{ds_ref}.{table}", not_found_ok=True)
        run(qualify(create, project, dataset))
        run(qualify(insert, project, dataset))
        print(f"  Created {table} with {len(parse_values(insert))} sample rows")

    sample_ts = next(iter(run(f"SELECT MAX(window_start) AS ts FROM {fqn('domains_30d')}"))).ts
    sample_str = sample_ts.strftime("%Y-%m-%d %H:%M:%S+00")

    for table in EXPAND_ORDER:
        if table not in schemas:
            continue
        cols = schemas[table][0]
        run(expansion_sql(table, cols, fqn(table), fqn("domains_30d"), sample_str, days))
        n = next(iter(run(f"SELECT COUNT(*) AS n FROM {fqn(table)}"))).n
        print(f"  Expanded {table} to {days} windows: {n} rows")

    if rebase:
        yesterday = dt.datetime.now(dt.timezone.utc).date() - dt.timedelta(days=1)
        shift = (yesterday - sample_ts.date()).days
        if shift:
            for table in schemas:
                run(shift_sql(table, fqn(table), shift))
            print(f"  Shifted all windows by {shift:+d} days (latest window = {yesterday})")

    print(f"\nDone. https://console.cloud.google.com/bigquery?project={project}&ws=!1m4!1m3!3m2!1s{project}!2s{dataset}")


def verify(project: str, dataset: str) -> int:
    """Run every rule statement; print rows returned. Returns number of failures."""
    _, client = _client(project)
    failures = 0
    for path in sorted(RULES_DIR.glob("*.sql")):
        print(f"\n{path.name}")
        for stmt in split_statements(path.read_text(encoding="utf-8")):
            if not re.search(r"^\s*SELECT", stmt, re.I | re.M):
                continue
            m = re.search(r"--\s*(RULE\s+\d+\s*[—-]\s*[^\n]+)", stmt)
            label = m.group(1).strip() if m else stmt.splitlines()[0][:60]
            try:
                rows = list(client.query(qualify(stmt, project, dataset)).result())
                flag = "" if rows else "   <-- returns nothing"
                print(f"  {len(rows):4d} rows  {label}{flag}")
            except Exception as exc:  # noqa: BLE001 — report and keep going
                failures += 1
                print(f"  FAIL       {label}: {str(exc).splitlines()[0]}")
    return failures


def check() -> int:
    """Offline validation of the schema files. Returns number of failures."""
    failures = 0
    for path in sorted(SCHEMA_DIR.glob("*.sql")):
        try:
            table, cols, _, insert = load_schema_file(path)
            print(f"  ok  {path.name}: {table}, {len(cols)} columns, {len(parse_values(insert))} rows")
        except ValueError as exc:
            failures += 1
            print(f"  FAIL {exc}")
    return failures


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--project", default=DEFAULT_PROJECT)
    parser.add_argument("--dataset", default=DEFAULT_DATASET)
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS, help="daily windows to generate (default 30)")
    parser.add_argument("--no-rebase", action="store_true", help="keep the sample dates instead of ending yesterday")
    parser.add_argument("--verify", action="store_true", help="after deploying, run every detection rule")
    parser.add_argument("--verify-only", action="store_true", help="only run the detection rules")
    parser.add_argument("--check", action="store_true", help="offline: validate schema files and exit")
    args = parser.parse_args()

    if args.check:
        sys.exit(1 if check() else 0)
    if not args.verify_only:
        if check():
            sys.exit("schema files are invalid; nothing deployed")
        deploy(args.project, args.dataset, args.days, rebase=not args.no_rebase)
    if args.verify or args.verify_only:
        sys.exit(1 if verify(args.project, args.dataset) else 0)


if __name__ == "__main__":
    main()
