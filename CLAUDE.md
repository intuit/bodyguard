# Bodyguard — AI Agent for Security Rules

**Presented at [Black Hat SecTor 2026 Arsenal — "Who is my Bodyguard? Demystifying Enterprise Security Rules with an AI Agent"](https://blackhat.com/sector/arsenal/schedule/index.html#who-is-my-bodyguard-demystifying-enterprise-security-rules-with-an-ai-agent-54853)**

## Project Overview

### The Problem

Enterprise security suffers from a visibility gap: **documentation describes theory, code describes reality.** Management makes strategic decisions based on scattered, outdated Confluence pages, while actual security defenses live in Git repositories. Siloed teams cannot verify what is really running in production, breaking collaboration and undermining security posture.

### The Solution

Bodyguard is a local, Dockerized RAG agent that acts as a translator between raw security code and enterprise stakeholders. It:

- Ingests security code (SQL detection rules, Python logic) and documentation (Markdown, Confluence)
- Builds a knowledge base (FAISS vectors + BM25 index over the same chunks)
- Lets engineers and leadership ask plain-language questions about deployed defenses, with every fact attributed to a file
- Optionally runs live queries against BigQuery to show real examples from production data

The three promises of the talk abstract — *theory vs. reality*, *data-driven leadership decisions*, *breaking team silos* — each map to a use case in the README, reproducible on the demo KB.

## Architecture

### Core Stack

- **LLM**: Ollama via `ChatOllama` (chat endpoint, real `system` role), `num_ctx=16384`, `temperature=0.1`. Default model `llama3.2`.
- **Embeddings**: `jina-embeddings-v2-base-en` via Ollama.
- **Retrieval**: `HybridRetriever` in `agent/core.py` — BM25 (`rank_bm25`) + FAISS MMR (`k=6, fetch_k=20, λ=0.7`), fused with reciprocal rank fusion, capped at 2 chunks per source file.
- **Chunking** (`kb/builder.py`): `.sql` → one chunk per statement (a rule and its header comment stay together); `.md` → heading-aware, 2000 chars; every chunk starts with a `[file: NAME]` tag so the LLM can cite it.
- **Interfaces**: Flask web UI (`web/`, streaming over SSE), CLI (`main.py`), Slack bot (`slack/bot.py`), REST (`/ask`, `/ask/stream`, `/health`).

### Why these choices (all verified against the demo KB)

- Ollama's default context is 2048 tokens; the system prompt alone is ~2000. Without `num_ctx` the prompt was silently truncated and the model ignored its rules.
- `OllamaLLM` (completion endpoint) flattened the chat template into one user string: no system role, rules ignored, and at low temperature the model continued the transcript with fake `Human:` turns. `ChatOllama` fixed all three.
- 1000-char chunks cut rules in half and ranked sample-data blocks above the rule itself; whole-file chunks let one multi-rule file dilute each rule. One-statement chunks are the sweet spot.
- Pure dense retrieval missed the SQLi and DDoS rules for questions that literally contained "SQL injection" / "DDoS" — the LLM then invented a file. BM25 fusion fixed it.
- Few-shot answers containing concrete SQL were parroted back for unrelated questions on a 3B model. The prompt now describes the answer shape without a worked example.

### System Prompt

`agent/prompts.md` **is** the prompt — everything in it is sent to the model, so it must be written for the model (no human-facing "how to customise" prose; that lives in the README). `REDTEAM.md` is appended when present. Both are read in `load_agent()`; editing them requires an app restart, not a KB rebuild.

## Development & Testing

```bash
make setup-dev   # venv (Python 3.10+, auto-detected) + runtime deps + pytest + matplotlib
make build       # demo KB from test/demo
make run         # web app on :5001
make test        # unit tests, no Ollama needed
```

`make setup` refuses Python < 3.10 (macOS's Xcode `python3` is 3.9). Override the interpreter with `SYSTEM_PYTHON=`.

### Demo knowledge base (`test/demo/`)

Two folders on purpose — "the code lives here, the docs live there" is the talk's premise:

- `detection-rules/` — **code.** `phishing.sql` (owner brand-protection-team), `malware.sql` (threat-hunting-team), `web_attack.sql` (appsec-team), three rules each, BigQuery Standard SQL referencing `bodyguard_demo.<table>`. Distinct owners exist so the "silo" use case is demonstrable. `schema/{urls,domains,ip}_30d.sql` + `schema/ip_reputation.sql` hold `CREATE TABLE` + one daily window of sample rows; `README.md` is the repo's own readme (owners, tables).
- `security-wiki/` — **docs.** One runbook per team. Each **deliberately disagrees** with its code, differently: `phishing_algorithm.md` (tables `waf_raw_events`/`waf_aggregated` vs `domains_30d`/`urls_30d`; regex vs `typosquatting_score`; a subdomain-depth check the code lacks), `c2_detection_runbook.md` (threshold 50 vs 100; claims an `ip_reputation` join and Tor coverage that `malware.sql` does not have), `web_attack_coverage.md` (leadership coverage matrix: threshold 500 vs 1000; a "Rule 2b" for Tor and a "Rule 4" for scanners that do not exist; SQLi "stacked queries" not in the regex). The README's use-case table lists them. Do not "fix" these — they are the theory-vs-reality demo.

Data conventions: IPs are RFC 5737 documentation ranges only, ASNs are RFC 5398 documentation numbers with fictional operator names (enforced by `tests/test_bq_demo.py`); `198.51.100.50` is a scanner in the data *and* in the reputation feed, and only `REDTEAM.md` says it is authorised. `203.0.113.55` is its hostile twin. Never end a comment line with `;` — both `kb/builder.py` and `scripts/deploy_bq.py` split statements there (also tested).

BigQuery: `make deploy-bq` runs `scripts/deploy_bq.py --verify`, which (re)creates the four tables from the schema files, expands the `*_30d` tables to 30 daily windows (deterministic jitter; young domains only from registration day, DDoS bursts, scanners every third day), rebases the windows to end yesterday, then runs all nine rules and prints row counts. `--check` validates the schema files offline. The schema files are the only source of truth: never hand-edit rows in the deploy script.

### Retrieval diagnostics

When answers look wrong, check retrieval before blaming the model:

```python
from langchain_community.vectorstores import FAISS
from langchain_ollama import OllamaEmbeddings
from agent.core import HybridRetriever
vs = FAISS.load_local("vector_store", OllamaEmbeddings(model="jina/jina-embeddings-v2-base-en"), allow_dangerous_deserialization=True)
for d in HybridRetriever(vs).invoke("Show me the code that detects SQL injection."):
    print(d.metadata["source"], d.page_content[:80])
```

## Field Notes (2026-09-10 review pass)

Things learned the hard way; each cost an hour. Check them before re-deriving.

- **A BigQuery call that "hangs" is almost never BigQuery.** On networks with TLS interception (corporate proxies), Python's `certifi` bundle lacks the corporate root CA: `requests` fails instantly with `CERTIFICATE_VERIFY_FAILED` while `curl` works (it uses the OS keychain). Google's client libraries treat that as transient and retry with backoff for minutes — indistinguishable from a hang. `agent/tls.py` (`truststore`) makes Python trust the OS store; `web/app.py` also runs the whole call on a pool with a hard deadline so a Flask worker can never block on it. If the button shows a 403 instead, the ADC account has no `bigquery.jobs.create` on the project — `gcloud auth application-default login` with the right account.
- **Check retrieval before touching the prompt or the model.** Every "the model invented a file" episode in this project was a chunk that was not in the context. The diagnostics snippet above takes ten seconds; a prompt tweak takes an hour and usually makes something else worse (a closing "say you can't find it" reminder in the human turn made the 3B model refuse the red-team question with the IP row in front of it — see the comment in `_build_prompt_template`).
- **Retrieval settings beat embedding models.** Measured on the 28-chunk demo KB: swapping `jina` for `nomic-embed-text` moved the target chunk from rank 4 to rank 7 for the phantom-control question; going from `TOP_K=6` to `8` put every target chunk in the context on both embeddings. With three runbooks, six slots capped at two per file were filled entirely by Markdown.
- **What `llama3.2` (3B) can and cannot do on this KB**, with the right chunks retrieved: correct on concrete examples, code extraction, the full rule inventory with owners, and drift questions where the code is the evidence; unreliable on triage verdicts (red-team IP), the "not in the KB" refusal (it recites a neighbouring rule instead) and cross-topic gap analysis. Those need an 8B+ model — selectable per question from the sidebar, or `LLM_MODEL=`. The README's use cases state this per case; keep them honest if the KB or the prompt changes.
- **Prompt files are the model's, not yours.** Anything in `agent/prompts.md` or `REDTEAM.md` is sent verbatim; the 3B model recited "the agent would…" prose and a worked SQL example until both were removed. Human guidance goes in the README.
- **Ollama defaults bite silently**: `num_ctx` 2048 (the system prompt alone is ~2000 tokens — it was being truncated from the front), and `OllamaLLM` is the completion endpoint (no system role). Both are fixed in `agent/core.py`; do not "simplify" them away.
- **Restarting the server while someone is testing** shows them "Failed to fetch". Say so first.

## Key Files

| File | Purpose |
|---|---|
| `agent/core.py` | `HybridRetriever`, RAG chain, `load_agent()`, `load_system_prompt()` |
| `agent/prompts.md` | System prompt (model-facing only) |
| `REDTEAM.md` | Red-team allowlist appended to the prompt |
| `kb/builder.py` | Ingestion: local dir / GitHub / BigQuery → FAISS |
| `web/app.py` | Flask routes incl. SSE streaming and the BigQuery live queries (parameterised IP lookup when the question names an IPv4, topic sample query otherwise) |
| `web/templates/index.html`, `web/static/app.{css,js}` | Chat UI — vanilla, no CDN, light/dark |
| `main.py` | CLI |
| `slack/bot.py` | Slack Socket Mode bot |
| `scripts/deploy_bq.py` | Demo dataset for BigQuery |
| `tests/` | pytest unit tests |

## Security Considerations

- `agent/prompts.md` and `REDTEAM.md` ship with generic examples only; keep organisation-specific ranges out of git (`.gitignore` has a commented `REDTEAM.md` line).
- `FAISS.load_local(..., allow_dangerous_deserialization=True)` unpickles the docstore — only load indexes you built.
- The web UI has no auth; restrict access (VPN, firewall) if pointed at real security data.
- Use a read-only BigQuery service account.
- The Docker image runs as a non-root user; `docker-compose.yml` expects `./vector_store` to exist on the host first.

## Open Source

MIT licensed (see `LICENSE`). Intentionally generic — no employer-specific references, no proprietary schemas. The demo rules and runbook are fictional examples.
