"""
Bodyguard — Flask Web App

Usage:
    python -m web.app
Then open http://localhost:5001 in your browser.

Endpoints:
    GET  /               Chat UI
    POST /ask            {"question": str, "llm_model"?: str, "embed_model"?: str} -> {"answer", "sources", "show_bq"}
    POST /ask/stream     Same input, Server-Sent Events: {"token"} … {"done", "sources", "show_bq"}
    POST /query_bq       {"question": str, "answer": str} -> runs a live query against BigQuery:
                         an IP lookup when the question names an IPv4, otherwise the demo
                         query matching the answer's topic
    GET  /health         Ollama reachability, vector store presence, BigQuery availability
    GET  /models         Models available on the Ollama host
"""

from __future__ import annotations

import json
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from pathlib import Path

import requests as _requests
from flask import Flask, Response, jsonify, render_template, request, stream_with_context

from agent.core import load_agent
from agent.tls import use_system_trust_store

use_system_trust_store()  # before any HTTPS call (BigQuery); see agent/tls.py

# ---------------------------------------------------------------------------
# Config (overridable via env vars)
# ---------------------------------------------------------------------------
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
DEFAULT_EMBED_MODEL = os.getenv("EMBED_MODEL", "jina/jina-embeddings-v2-base-en")
DEFAULT_LLM_MODEL = os.getenv("LLM_MODEL", "llama3.2")
VECTOR_STORE = Path(os.getenv("VECTOR_STORE", "vector_store"))
PORT = int(os.getenv("PORT", 5001))

BQ_PROJECT = os.getenv("BQ_PROJECT", "bodyguard-bh2026")
BQ_DATASET = os.getenv("BQ_DATASET", "bodyguard_demo")
BQ_TIMEOUT_S = int(os.getenv("BQ_TIMEOUT_S", 30))

# BigQuery calls run on their own small pool so a hung call (see query_bq) never
# ties up a request thread; the client is created lazily and reused.
_bq_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="bq")
_bq_client = None

# Chosen to work well on the default 3B model. Broader questions ("what rules do
# we have?", "any gaps in X?") are better served by a larger LLM — see README.
SAMPLE_QUESTIONS = [
    "How does our phishing protection work? Give me a concrete example with a URL.",
    "Show me the code that detects SQL injection.",
    "Is 198.51.100.50 an attacker? Should the SOC be worried?",
    "Is 203.0.113.55 attacking us? What do our data say about it?",
    "The runbook says Rule 2 checks for more than 3 subdomain levels. Show me the code of Rule 2 in phishing.sql — does that check exist?",
    "The C2 runbook says any IP flagged malware_c2 in ip_reputation is alerted regardless of volume. Does malware.sql Rule 1 do that?",
]

app = Flask(__name__)  # templates/ and static/ resolve relative to this package

# Current agent + the config it was built with. Guarded by a lock: Flask serves
# requests on multiple threads and swapping models mid-request would race.
_agent = None
_agent_config: dict = {}
_agent_lock = threading.Lock()


def get_agent(llm_model: str, embed_model: str):
    global _agent, _agent_config
    config = {"llm": llm_model, "embed": embed_model}
    with _agent_lock:
        if _agent is None or config != _agent_config:
            _agent = load_agent(
                vector_store_path=VECTOR_STORE,
                ollama_host=OLLAMA_HOST,
                embed_model=embed_model,
                llm_model=llm_model,
            )
            _agent_config = config
        return _agent


def _bq_available() -> bool:
    try:
        import google.cloud.bigquery  # noqa: F401
        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# BigQuery live queries
# ---------------------------------------------------------------------------
# Two kinds of live query, both read-only against the demo dataset:
#
#   1. Entity lookup — the *question* names an IPv4 address. We pull that IP's
#      behaviour from ip_30d (every daily window) joined to the reputation feed
#      (ip_reputation). The address travels as a query parameter, never by
#      string interpolation: it comes from user input.
#   2. Topic example — otherwise, a canned sample query chosen from the
#      detection topic of the agent's *answer* (phishing, C2, XSS, …), limited
#      to the most recent daily window so the same entity is not repeated 30×.
#
# Both are offered only when the agent actually answered (not on a decline),
# except the IP lookup: an IP the knowledge base does not know about is exactly
# when checking the data is most useful.

# Exactly four octets, each 0-255; lookarounds reject "1.2.3.4.5" and "10.0.0.300".
_IPV4_RE = re.compile(r"(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\d.])")

_BQ_KEYWORDS = (
    "phishing", "brand impersonation", "credential harvesting", "token theft",
    "c2", "beaconing", "malware", "payload", "distribution",
    "xss", "cross-site", "cross site scripting",
    "sql injection", "sqli", "union select",
    "ddos", "flood", "volumetric",
    "reputation", "tor exit", "vpn", "datacenter", "scanner", "nuclei", "zgrab",
    "detection rule", "attack", "threat", "blocked", "suspicious domain",
    "give me an example", "show me an example", "example from",
)

# If the agent's reply matches any of these, it declined the question — never show BQ button
_DECLINE_PATTERNS = (
    "i only answer security",
    "only answer security questions",
    "can't find that in the knowledge base",
    "outside my focus",
    "not a security",
    "can't help with that",
    "cannot help with that",
)

_LATEST = "(SELECT MAX(window_start) FROM {t})"

# (topic label, trigger keywords, SQL). Placeholders: {urls} {domains} {ips} {rep}
# are fully-qualified table names. First match wins; last entry is the fallback.
_BQ_QUERIES = [
    ("Phishing", ("phishing", "brand impersonation", "credential harvesting", "token theft"), f"""
        SELECT url, host, path, blocked_count, unique_ips, top_country, rule_id, action
        FROM {{urls}}
        WHERE action = 'block'
          AND rule_id LIKE 'CF_PHISHING%'
          AND window_start = {_LATEST.format(t='{urls}')}
        ORDER BY blocked_count DESC
        LIMIT 8"""),
    ("Malware / C2", ("c2", "beaconing", "malware", "payload", "distribution"), f"""
        SELECT b.client_ip, b.top_asn, b.top_country, b.visits, b.request_rate_per_h,
               b.unique_paths, b.top_http_method, b.error_rate, b.top_user_agent, b.top_host,
               r.category AS reputation
        FROM {{ips}} b
        LEFT JOIN {{rep}} r ON r.ip = b.client_ip
        WHERE b.is_datacenter = TRUE
          AND b.request_rate_per_h > 100
          AND b.error_rate < 0.05
          AND b.window_start = {_LATEST.format(t='{ips}')}
        ORDER BY b.request_rate_per_h DESC
        LIMIT 8"""),
    ("XSS", ("xss", "cross-site", "cross site"), f"""
        SELECT url, host, path, query_string, blocked_count, top_country
        FROM {{urls}}
        WHERE action = 'block'
          AND rule_id = 'CF_XSS_001'
          AND window_start = {_LATEST.format(t='{urls}')}
        LIMIT 8"""),
    ("SQL injection", ("sql injection", "sqli", "union select"), f"""
        SELECT url, host, path, query_string, blocked_count, top_user_agent, top_country
        FROM {{urls}}
        WHERE action = 'block'
          AND rule_id = 'CF_SQLI_001'
          AND window_start = {_LATEST.format(t='{urls}')}
        LIMIT 8"""),
    ("DDoS", ("ddos", "flood", "volumetric"), f"""
        SELECT window_start, client_ip, top_asn, top_country, visits, request_rate_per_h,
               blocked_count, error_rate, top_user_agent
        FROM {{ips}}
        WHERE request_rate_per_h > 1000
          AND error_rate > 0.95
        ORDER BY window_start DESC, request_rate_per_h DESC
        LIMIT 8"""),
    ("IP reputation", ("reputation", "tor exit", "vpn", "datacenter", "scanner", "nuclei", "zgrab"), f"""
        SELECT r.ip, r.category, r.source_feed, r.confidence, r.last_seen,
               b.visits, b.blocked_count, b.unique_paths, b.request_rate_per_h, b.top_user_agent
        FROM {{rep}} r
        LEFT JOIN {{ips}} b
          ON b.client_ip = r.ip AND b.window_start = {_LATEST.format(t='{ips}')}
        ORDER BY r.confidence DESC
        LIMIT 12"""),
    ("Most-blocked domains", (), f"""
        SELECT domain, impersonated_brand, typosquatting_score,
               visits, blocked_count, top_country, domain_age_days
        FROM {{domains}}
        WHERE blocked_count > 0
          AND window_start = {_LATEST.format(t='{domains}')}
        ORDER BY blocked_count DESC
        LIMIT 8"""),
]

_IP_LOOKUP_SQL = """
    SELECT
      q.ip AS client_ip, b.window_start, b.visits, b.blocked_count, b.unique_paths,
      b.request_rate_per_h, b.top_http_method, b.error_rate, b.top_user_agent, b.top_host,
      b.top_asn, b.top_country, b.is_tor_exit, b.is_vpn, b.is_datacenter,
      r.category AS reputation, r.source_feed, r.confidence, r.notes AS reputation_notes
    FROM (SELECT @ip AS ip) q
    LEFT JOIN {ips} b ON b.client_ip = q.ip
    LEFT JOIN {rep} r ON r.ip = q.ip
    ORDER BY b.window_start DESC
    LIMIT 10"""


def _tables() -> dict:
    fqn = lambda t: f"`{BQ_PROJECT}.{BQ_DATASET}.{t}`"  # noqa: E731
    return {"urls": fqn("urls_30d"), "domains": fqn("domains_30d"),
            "ips": fqn("ip_30d"), "rep": fqn("ip_reputation")}


def _find_ip(text: str) -> str | None:
    m = _IPV4_RE.search(text or "")
    return m.group(1) if m else None


def _wants_bq(answer: str, question: str = "") -> bool:
    """True when a live query would add something: the question names an IP,
    or the answer is a security-topic response (not a decline)."""
    if _find_ip(question):
        return True
    lower = (answer or "").lower()
    if any(p in lower for p in _DECLINE_PATTERNS):
        return False
    return any(kw in lower for kw in _BQ_KEYWORDS)


def _pick_bq_query(answer: str, question: str = "") -> tuple[str, str, list[tuple[str, str, str]]]:
    """Return (topic, sql, params). params are (name, bq_type, value) triples."""
    tables = _tables()
    ip = _find_ip(question)
    if ip:
        return f"IP lookup · {ip}", _IP_LOOKUP_SQL.format(**tables).strip(), [("ip", "STRING", ip)]
    lower = (answer or "").lower()
    for topic, keywords, sql in _BQ_QUERIES:
        if not keywords or any(k in lower for k in keywords):
            return topic, sql.format(**tables).strip(), []
    raise AssertionError("unreachable: last _BQ_QUERIES entry has no keywords")


def get_ollama_models() -> dict:
    """Return {'llm': [...], 'embed': [...]} from the running Ollama instance."""
    try:
        resp = _requests.get(f"{OLLAMA_HOST}/api/tags", timeout=3)
        resp.raise_for_status()
        models = [m["name"] for m in resp.json().get("models", [])]
        # Heuristic split: embedding models usually have embed/jina/nomic in name
        embed_keywords = ("embed", "jina", "nomic", "bge", "e5")
        embed = [m for m in models if any(k in m.lower() for k in embed_keywords)]
        llm = [m for m in models if m not in embed]
        return {"llm": llm or models, "embed": embed or models}
    except Exception:
        return {"llm": [DEFAULT_LLM_MODEL], "embed": [DEFAULT_EMBED_MODEL]}


def _ollama_reachable() -> bool:
    try:
        return _requests.get(f"{OLLAMA_HOST}/api/tags", timeout=2).ok
    except Exception:
        return False


def _question_and_models():
    data = request.get_json(force=True, silent=True) or {}
    question = (data.get("question") or "").strip()
    llm_model = data.get("llm_model") or DEFAULT_LLM_MODEL
    embed_model = data.get("embed_model") or DEFAULT_EMBED_MODEL
    return question, llm_model, embed_model


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template(
        "index.html",
        models=get_ollama_models(),
        default_llm=DEFAULT_LLM_MODEL,
        default_embed=DEFAULT_EMBED_MODEL,
        sample_questions=SAMPLE_QUESTIONS,
        bq_available=_bq_available(),
        bq_target=f"{BQ_PROJECT}.{BQ_DATASET}",
    )


@app.route("/ask", methods=["POST"])
def ask_endpoint():
    question, llm_model, embed_model = _question_and_models()
    if not question:
        return jsonify({"error": "No question provided."}), 400

    try:
        result = get_agent(llm_model, embed_model).ask(question)
        result["show_bq"] = _wants_bq(result.get("answer", ""), question)
        return jsonify(result)
    except FileNotFoundError as exc:
        return jsonify({"error": str(exc)}), 503
    except Exception as exc:
        app.logger.exception("Agent error")
        return jsonify({"error": str(exc)}), 500


@app.route("/ask/stream", methods=["POST"])
def ask_stream():
    """Server-Sent Events: one JSON object per `data:` line."""
    question, llm_model, embed_model = _question_and_models()
    if not question:
        return jsonify({"error": "No question provided."}), 400

    def sse(payload: dict) -> str:
        return f"data: {json.dumps(payload)}\n\n"

    def generate():
        try:
            agent = get_agent(llm_model, embed_model)
            answer_parts: list[str] = []
            for event in agent.stream(question):
                if "token" in event:
                    answer_parts.append(event["token"])
                    yield sse(event)
                elif event.get("done"):
                    event["show_bq"] = _wants_bq("".join(answer_parts), question)
                    yield sse(event)
        except Exception as exc:  # surfaced in-stream; HTTP status is already 200
            app.logger.exception("Agent error (stream)")
            yield sse({"error": str(exc)})

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/query_bq", methods=["POST"])
def query_bq():
    """
    Run a live, read-only query against the demo dataset: an IP lookup when the
    question names an IPv4 address, otherwise the sample query matching the
    detection topic of the agent's answer. See _pick_bq_query.
    """
    try:
        from google.cloud import bigquery as bq
    except ImportError:
        return jsonify({"error": "google-cloud-bigquery not installed"}), 500

    data = request.get_json(force=True, silent=True) or {}
    topic, sql, params = _pick_bq_query(data.get("answer") or "", data.get("question") or "")
    # What the UI shows under "Show SQL": the parameter values as a comment.
    shown_sql = "".join(f"-- @{n} = '{v}'\n" for n, _, v in params) + sql

    def run() -> list:
        global _bq_client
        if _bq_client is None:
            _bq_client = bq.Client(project=BQ_PROJECT)
        config = bq.QueryJobConfig(
            query_parameters=[bq.ScalarQueryParameter(n, t, v) for n, t, v in params],
        )
        job = _bq_client.query(sql, job_config=config, timeout=BQ_TIMEOUT_S)
        return list(job.result(timeout=BQ_TIMEOUT_S))

    # Hard deadline around the whole call, client creation included: credential
    # loading (google.auth) can hang with a stale ADC file or a blocked metadata
    # endpoint, and the per-request timeouts above never get a chance to fire.
    # Without this, a Flask worker blocks forever and the browser only sees
    # "Failed to fetch".
    try:
        rows = _bq_pool.submit(run).result(timeout=BQ_TIMEOUT_S)
    except FuturesTimeout:
        app.logger.error("BigQuery call exceeded %ss", BQ_TIMEOUT_S)
        return jsonify({
            "error": (f"BigQuery did not answer within {BQ_TIMEOUT_S}s. Check that "
                      "`gcloud auth application-default login` is current and that "
                      "googleapis.com is reachable (VPN?)."),
            "query": shown_sql,
        }), 504
    except Exception as e:
        app.logger.exception("BigQuery error")
        return jsonify({"error": str(e) or type(e).__name__, "query": shown_sql}), 502

    columns = list(rows[0].keys()) if rows else []
    result_rows = [
        {col: "" if row[col] is None else str(row[col]) for col in columns}
        for row in rows
    ]
    return jsonify({"topic": topic, "table": columns, "rows": result_rows, "query": shown_sql})


@app.route("/health")
def health():
    ollama_ok = _ollama_reachable()
    kb_ok = VECTOR_STORE.exists()
    status = {
        "status": "ok" if (ollama_ok and kb_ok) else "degraded",
        "ollama": {"host": OLLAMA_HOST, "reachable": ollama_ok},
        "vector_store": {"path": str(VECTOR_STORE), "present": kb_ok},
        "bigquery": {"available": _bq_available(), "target": f"{BQ_PROJECT}.{BQ_DATASET}"},
    }
    return jsonify(status), (200 if status["status"] == "ok" else 503)


@app.route("/models")
def models_endpoint():
    return jsonify(get_ollama_models())


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
