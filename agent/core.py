"""Bodyguard Agent — Core RAG chain."""

from __future__ import annotations

import os
import re
from pathlib import Path

from langchain_community.vectorstores import FAISS
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_ollama import ChatOllama, OllamaEmbeddings
from rank_bm25 import BM25Okapi

DEFAULT_OLLAMA_HOST = "http://localhost:11434"
DEFAULT_EMBED_MODEL = "jina/jina-embeddings-v2-base-en"
DEFAULT_LLM_MODEL = "llama3.2"
DEFAULT_VECTOR_STORE = Path("vector_store")
TOP_K = 8        # chunks handed to the LLM (6 starved the code once a KB had 3+ runbooks)
FETCH_K = 20     # candidates considered by MMR before picking TOP_K diverse ones
MMR_LAMBDA = 0.7 # 1.0 = pure relevance, 0.0 = pure diversity
MAX_PER_SOURCE = 2  # chunks from the same file among the TOP_K (see HybridRetriever.invoke)

# Ollama defaults to a 2048-token window, which the system prompt alone nearly
# fills — the *beginning* (the system prompt) would be silently dropped. Sized
# for the ~2k-token prompt plus TOP_K whole SQL files (kb.builder keeps rule
# files intact up to 8000 chars). Every model we ship with supports far more.
LLM_NUM_CTX = 16384
# Grounded Q&A over a knowledge base should not be creative. (Not 0: small
# models tend to fall into repetition loops when fully greedy.)
LLM_TEMPERATURE = 0.1
# Thinking models (qwen3, deepseek-r1, …): None = model default, LLM_REASONING=0 = off.
# The reasoning trace never reaches the answer either way; this only trades latency.
_reasoning_env = os.getenv("LLM_REASONING")
LLM_REASONING = None if _reasoning_env is None else _reasoning_env.strip().lower() not in ("0", "false", "no", "off")

_ROOT = Path(__file__).resolve().parent.parent
PROMPT_PATH = _ROOT / "agent" / "prompts.md"
REDTEAM_PATH = _ROOT / "REDTEAM.md"


def load_system_prompt(prompt_path: Path = PROMPT_PATH, redteam_path: Path = REDTEAM_PATH) -> str:
    """Return the system prompt: agent/prompts.md, plus REDTEAM.md appended when present.

    Called every time an agent is built, so editing either file only requires
    restarting the app — no knowledge-base rebuild.
    """
    if not prompt_path.exists():
        raise FileNotFoundError(f"System prompt not found at {prompt_path}")

    prompt = prompt_path.read_text(encoding="utf-8")

    if redteam_path.exists():
        prompt += "\n\n---\n\n" + redteam_path.read_text(encoding="utf-8")

    return prompt


def _build_prompt_template() -> ChatPromptTemplate:
    return ChatPromptTemplate.from_messages([
        ("system", load_system_prompt()),
        # Keep this message bare. A closing "if the context lacks the answer, say you
        # can't find it" reminder was tried here and made the 3B model over-refuse
        # (it declined the red-team question with the IP row right in front of it).
        # The grounding rules in the system prompt are sufficient.
        ("human", "Context from knowledge base:\n{context}\n\nQuestion: {question}"),
    ])


def _format_docs(docs) -> str:
    return "\n\n---\n\n".join(doc.page_content for doc in docs)


def _bm25_tokens(text: str) -> list[str]:
    # Lower-case word tokens so "SQL injection" matches "SQL Injection (SQLi)"
    # and rule IDs like CF_SQLI_001 stay whole.
    return re.findall(r"\w+", text.lower())


class HybridRetriever:
    """BM25 (exact terms, rule IDs) + dense MMR (semantics), fused by reciprocal rank.

    Security questions are full of literal keywords — "SQL injection", "DDoS",
    "CF_PHISHING_001" — that embedding models regularly miss while a lexical
    index cannot. Each retriever proposes TOP_K chunks; RRF merges the two
    rankings and the best TOP_K overall are returned.
    """

    RRF_K = 60  # standard reciprocal-rank-fusion constant

    def __init__(self, vector_store: FAISS):
        self._vs = vector_store
        # The FAISS docstore holds every chunk we indexed; reuse it for BM25 so
        # both retrievers see exactly the same corpus.
        self._docs = list(vector_store.docstore._dict.values())
        self._bm25 = BM25Okapi([_bm25_tokens(d.page_content) for d in self._docs])

    def _lexical(self, question: str):
        scores = self._bm25.get_scores(_bm25_tokens(question))
        ranked = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
        return [self._docs[i] for i in ranked[:TOP_K] if scores[i] > 0]

    def _dense(self, question: str):
        return self._vs.max_marginal_relevance_search(
            question, k=TOP_K, fetch_k=FETCH_K, lambda_mult=MMR_LAMBDA
        )

    def invoke(self, question: str):
        fused: dict[str, float] = {}
        by_key = {}
        for ranking in (self._lexical(question), self._dense(question)):
            for rank, doc in enumerate(ranking):
                key = doc.page_content
                by_key[key] = doc
                fused[key] = fused.get(key, 0.0) + 1.0 / (self.RRF_K + rank + 1)
        ranked = [by_key[k] for k in sorted(fused, key=fused.get, reverse=True)]

        # A long runbook splits into many sections that all score well on broad
        # questions ("what rules do we have?") and would fill every slot. Cap
        # chunks per source file first, then backfill if slots remain.
        picked, per_source, overflow = [], {}, []
        for doc in ranked:
            src = doc.metadata.get("source", "")
            if per_source.get(src, 0) < MAX_PER_SOURCE:
                picked.append(doc)
                per_source[src] = per_source.get(src, 0) + 1
            else:
                overflow.append(doc)
            if len(picked) == TOP_K:
                break
        return (picked + overflow)[:TOP_K]


def _sources(docs) -> list[str]:
    # Preserve retrieval order (most relevant first) while de-duplicating.
    seen: dict[str, None] = {}
    for doc in docs:
        seen.setdefault(doc.metadata.get("source", "unknown"), None)
    return list(seen)


class BodyguardAgent:
    """Wraps the LCEL chain and the retriever so callers can get sources."""

    def __init__(self, retriever, chain):
        self._retriever = retriever
        self._chain = chain

    def retrieve(self, question: str):
        """The TOP_K chunks the answer will be grounded in."""
        return self._retriever.invoke(question)

    def ask(self, question: str) -> dict:
        docs = self.retrieve(question)
        context = _format_docs(docs)
        answer = self._chain.invoke({"context": context, "question": question})
        return {"answer": answer, "sources": _sources(docs)}

    def stream(self, question: str):
        """Yield SSE-ready dicts: {"token": str} per chunk, then {"done": True, "sources": [...]}."""
        docs = self.retrieve(question)
        context = _format_docs(docs)
        for chunk in self._chain.stream({"context": context, "question": question}):
            yield {"token": chunk}
        yield {"done": True, "sources": _sources(docs)}


def load_agent(
    vector_store_path: Path | str = DEFAULT_VECTOR_STORE,
    ollama_host: str = DEFAULT_OLLAMA_HOST,
    embed_model: str = DEFAULT_EMBED_MODEL,
    llm_model: str = DEFAULT_LLM_MODEL,
) -> BodyguardAgent:
    """Load the FAISS index and return a ready-to-use BodyguardAgent."""
    vector_store_path = Path(vector_store_path)

    if not vector_store_path.exists():
        raise FileNotFoundError(
            f"Vector store not found at '{vector_store_path}'. "
            "Run `python -m kb.builder --source test/demo --output vector_store` "
            "(or `make build`) first to build the knowledge base."
        )

    embeddings = OllamaEmbeddings(model=embed_model, base_url=ollama_host)
    vector_store = FAISS.load_local(
        str(vector_store_path),
        embeddings,
        allow_dangerous_deserialization=True,  # FAISS local stores are pickled; only load indexes you built
    )
    retriever = HybridRetriever(vector_store)

    # ChatOllama uses Ollama's /api/chat so the system prompt is sent with a real
    # `system` role. (OllamaLLM = /api/generate would flatten the messages into
    # one user string; small models then ignore the rules and even continue the
    # transcript with fake "Human:" turns.)
    llm = ChatOllama(
        model=llm_model,
        base_url=ollama_host,
        num_ctx=LLM_NUM_CTX,
        temperature=LLM_TEMPERATURE,
        reasoning=LLM_REASONING,
    )
    chain = _build_prompt_template() | llm | StrOutputParser()

    return BodyguardAgent(retriever=retriever, chain=chain)


def ask(agent: BodyguardAgent, question: str) -> dict:
    """Convenience wrapper used by web/app.py, main.py, and slack/bot.py."""
    return agent.ask(question)
