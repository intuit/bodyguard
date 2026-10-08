"""Demo dataset + BigQuery glue. No network, no Ollama, no google-cloud calls."""

from pathlib import Path

import pytest

from scripts import deploy_bq
from web import app as webapp

SCHEMA_FILES = sorted(deploy_bq.SCHEMA_DIR.glob("*.sql"))
RULE_FILES = sorted(deploy_bq.RULES_DIR.glob("*.sql"))


# ── Schema files are the single source of truth for the deployed tables ────────

def test_schema_dir_has_the_four_demo_tables():
    assert {p.stem for p in SCHEMA_FILES} == {"domains_30d", "ip_30d", "ip_reputation", "urls_30d"}


@pytest.mark.parametrize("path", SCHEMA_FILES, ids=lambda p: p.name)
def test_every_sample_row_matches_the_column_count(path: Path):
    table, cols, _, insert = deploy_bq.load_schema_file(path)  # raises on arity mismatch
    assert table == path.stem
    assert len(deploy_bq.parse_values(insert)) >= 10


def test_parse_values_handles_quotes_comments_and_nulls():
    stmt = """INSERT INTO t VALUES
    -- a comment with (parens) and a ; semicolon
    ('a''b', 1, NULL, TRUE),   -- trailing comment
    ('x=<img onerror=fetch("u")>', 2.5, 'n', FALSE);"""
    rows = deploy_bq.parse_values(stmt)
    assert rows == [["'a''b'", "1", "NULL", "TRUE"],
                    ["'x=<img onerror=fetch(\"u\")>'", "2.5", "'n'", "FALSE"]]


def test_column_names_ignore_header_parentheses_and_primary_key():
    stmt = """-- Purpose: one row per (thing, day)
    CREATE TABLE IF NOT EXISTS bodyguard_demo.t (
        a STRING NOT NULL,   -- (comment)
        -- a comment line
        b INT64,
        PRIMARY KEY (a) NOT ENFORCED
    );"""
    assert deploy_bq.table_name(stmt) == "t"
    assert deploy_bq.column_names(stmt) == ["a", "b"]


def test_split_statements_keeps_header_comment_and_drops_comment_only_fragments():
    sql = "-- header\nSELECT 1;\n\n-- trailing comment\n"
    assert deploy_bq.split_statements(sql) == ["-- header\nSELECT 1;"]
    # A ';' ending a comment line is a statement boundary — the header is cut off.
    assert deploy_bq.split_statements("-- header;\nSELECT 1;\n") == ["SELECT 1;"]


def test_qualify_rewrites_dataset_references():
    out = deploy_bq.qualify("FROM bodyguard_demo.urls_30d u JOIN bodyguard_demo.domains_30d d", "p-1", "ds")
    assert out == "FROM `p-1.ds.urls_30d` u JOIN `p-1.ds.domains_30d` d"


def test_no_comment_line_ends_with_a_semicolon():
    """`;` at end of line is a statement boundary for both deploy_bq and kb.builder."""
    offenders = []
    for path in SCHEMA_FILES + RULE_FILES:
        for i, line in enumerate(path.read_text().splitlines(), 1):
            if line.lstrip().startswith("--") and line.rstrip().endswith(";"):
                offenders.append(f"{path.name}:{i}")
    assert not offenders, offenders


def test_expansion_sql_covers_every_column_once():
    table, cols, _, _ = deploy_bq.load_schema_file(deploy_bq.SCHEMA_DIR / "ip_30d.sql")
    sql = deploy_bq.expansion_sql(table, cols, "`p.d.ip_30d`", "`p.d.domains_30d`", "2026-09-09 00:00:00+00", 30)
    for c in cols:
        assert f" AS {c}" in sql
    assert "GENERATE_ARRAY(1, 29)" in sql
    assert "n IN (1, 15)" in sql  # DDoS bursts


# ── The demo tells a consistent story across files ─────────────────────────────

def _text(*names: str) -> str:
    return "\n".join((deploy_bq.RULES_DIR / "schema" / n).read_text() for n in names)


def test_red_team_scanner_is_in_the_data_and_on_the_allowlist():
    redteam = (deploy_bq.REPO_ROOT / "REDTEAM.md").read_text()
    assert "198.51.100.50" in redteam
    assert "198.51.100.50" in _text("ip_30d.sql")
    assert "198.51.100.50" in _text("ip_reputation.sql")  # the feed calls it a scanner


def test_only_documentation_ip_ranges_are_used():
    """RFC 5737 ranges only — the repo is public and the rows label IPs as attackers."""
    import re
    text = _text("ip_30d.sql", "ip_reputation.sql", "urls_30d.sql", "domains_30d.sql")
    ips = set(re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text))
    bad = {ip for ip in ips if not ip.startswith(("192.0.2.", "198.51.100.", "203.0.113."))}
    assert not bad, bad


def test_rules_reference_only_dataset_qualified_tables():
    import re
    for path in RULE_FILES:
        for m in re.finditer(r"\b(?:FROM|JOIN)\s+([\w.`]+)", path.read_text()):
            assert m.group(1).startswith("bodyguard_demo."), f"{path.name}: {m.group(0)}"


# ── web.app glue ───────────────────────────────────────────────────────────────

def test_ip_in_question_always_offers_a_live_lookup():
    assert webapp._wants_bq("I can't find that in the knowledge base.", "Is 203.0.113.55 attacking us?")
    assert not webapp._wants_bq("I can't find that in the knowledge base.", "Do we have EDR rules?")
    assert not webapp._wants_bq("I only answer security questions.", "What is the weather?")
    assert webapp._wants_bq("Three phishing rules cover …", "")


def test_ip_lookup_is_parameterised_not_interpolated():
    topic, sql, params = webapp._pick_bq_query("whatever", "Is 198.51.100.50 an attacker?")
    assert topic == "IP lookup · 198.51.100.50"
    assert params == [("ip", "STRING", "198.51.100.50")]
    assert "198.51.100.50" not in sql and "@ip" in sql
    assert "ip_30d" in sql and "ip_reputation" in sql


def test_topic_queries_pick_by_answer_and_fall_back():
    assert webapp._pick_bq_query("The C2 beaconing rule flags …", "")[0] == "Malware / C2"
    assert webapp._pick_bq_query("Tor exit nodes in the reputation feed", "")[0] == "IP reputation"
    topic, sql, params = webapp._pick_bq_query("nothing specific", "")
    assert topic == "Most-blocked domains" and params == []
    assert f"`{webapp.BQ_PROJECT}.{webapp.BQ_DATASET}.domains_30d`" in sql


def test_ipv4_regex_rejects_out_of_range_octets():
    assert webapp._find_ip("see 256.1.1.1 and 10.0.0.300") is None
    assert webapp._find_ip("see 1.2.3.4 ok") == "1.2.3.4"
    assert webapp._find_ip("version 1.2.3.4.5 is not an IP") is None
