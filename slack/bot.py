"""
Bodyguard — Slack Bot

Listens for @-mentions or DMs and answers security questions via the RAG agent.

Prerequisites:
  1. Create a Slack App at https://api.slack.com/apps
  2. Add OAuth scopes: app_mentions:read, chat:write, im:history, im:read
  3. Enable Socket Mode and generate an App-Level Token (xapp-…)
  4. Install the app to your workspace

Environment variables (required):
  SLACK_BOT_TOKEN   — xoxb-… (Bot User OAuth Token)
  SLACK_APP_TOKEN   — xapp-… (App-Level Token for Socket Mode)

Optional:
  OLLAMA_HOST, EMBED_MODEL, LLM_MODEL, VECTOR_STORE

Usage:
  python -m slack.bot
"""

from __future__ import annotations

import logging
import os
import re
import sys
from pathlib import Path

from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

from agent.core import ask, load_agent
from agent.tls import use_system_trust_store

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
log = logging.getLogger(__name__)
use_system_trust_store()  # Slack Socket Mode behind corporate TLS interception

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN")
SLACK_APP_TOKEN = os.getenv("SLACK_APP_TOKEN")
if not SLACK_BOT_TOKEN or not SLACK_APP_TOKEN:
    sys.exit(
        "SLACK_BOT_TOKEN (xoxb-…) and SLACK_APP_TOKEN (xapp-…) must be set. "
        "See the 'Slack Integration' section of the README."
    )

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
EMBED_MODEL = os.getenv("EMBED_MODEL", "jina/jina-embeddings-v2-base-en")
LLM_MODEL = os.getenv("LLM_MODEL", "llama3.2")
VECTOR_STORE = Path(os.getenv("VECTOR_STORE", "vector_store"))

# ---------------------------------------------------------------------------
# Load agent once at startup
# ---------------------------------------------------------------------------
log.info("Loading knowledge base …")
agent = load_agent(
    vector_store_path=VECTOR_STORE,
    ollama_host=OLLAMA_HOST,
    embed_model=EMBED_MODEL,
    llm_model=LLM_MODEL,
)
log.info("Agent ready.")

# ---------------------------------------------------------------------------
# Slack app
# ---------------------------------------------------------------------------
bolt_app = App(token=SLACK_BOT_TOKEN)


def _clean(text: str) -> str:
    return re.sub(r"<@[A-Z0-9]+>", "", text).strip()


def _respond(say, question: str, thread_ts: str | None = None) -> None:
    if not question:
        say(text="Ask me a security question — e.g. _How does our phishing detection work?_",
            thread_ts=thread_ts)
        return

    say(text=":mag: Thinking…", thread_ts=thread_ts)

    try:
        result = ask(agent, question)
        blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": result["answer"]}}]
        if result["sources"]:
            blocks.append({
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"*Sources:* {', '.join(result['sources'])}"}],
            })
        say(blocks=blocks, text=result["answer"], thread_ts=thread_ts)
    except Exception as exc:
        log.exception("Agent error")
        say(text=f":x: Error: {exc}", thread_ts=thread_ts)


@bolt_app.event("app_mention")
def handle_mention(event, say):
    _respond(say, _clean(event.get("text", "")), thread_ts=event.get("ts"))


@bolt_app.event("message")
def handle_dm(event, say):
    if event.get("bot_id") or event.get("channel_type") != "im":
        return
    _respond(say, _clean(event.get("text", "")), thread_ts=event.get("ts"))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    log.info("Starting Bodyguard Slack bot (Socket Mode) …")
    SocketModeHandler(bolt_app, SLACK_APP_TOKEN).start()
