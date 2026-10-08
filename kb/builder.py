#!/usr/bin/env python3
"""
Knowledge Base Builder — Bodyguard PoC

Ingests security code and documentation from a local directory, a GitHub
repository, OR a BigQuery dataset, splits the content with type-aware
splitters, embeds with Ollama, and saves a FAISS index to disk.

Usage:
    Local directory:
        python -m kb.builder --source test/demo --output vector_store

    GitHub repo:
        python -m kb.builder --github owner/security-rules --output vector_store

    BigQuery dataset:
        python -m kb.builder --bigquery myproject.bodyguard_demo --output vector_store

    Rebuild (overwrite):
        python -m kb.builder --bigquery myproject.bodyguard_demo --output vector_store --force

Environment variables:
    GITHUB_TOKEN        Personal access token (required for private repos)
    GOOGLE_CLOUD_PROJECT  GCP project (fallback if not in --bigquery argument)
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

from colorama import Fore, Style, init
from langchain_community.document_loaders import GithubFileLoader, TextLoader
from langchain_core.documents import Document
from langchain_community.vectorstores import FAISS
from langchain_ollama import OllamaEmbeddings
from langchain_text_splitters import MarkdownTextSplitter, RecursiveCharacterTextSplitter

from agent.tls import use_system_trust_store

init(autoreset=True)
use_system_trust_store()  # GitHub / BigQuery loaders behind corporate TLS interception

SUPPORTED_EXTENSIONS = {
    ".sql": "sql",
    ".md": "markdown",
    ".py": "code",
    ".txt": "text",
}

DEFAULT_OLLAMA_HOST = "http://localhost:11434"
DEFAULT_EMBED_MODEL = "jina/jina-embeddings-v2-base-en"
DEFAULT_CHUNK_SIZE = 2000
DEFAULT_CHUNK_OVERLAP = 200

# A detection rule is only meaningful whole: a WHERE clause split from its
# header comment retrieves badly and makes the LLM guess, while a whole file
# holding several rules dilutes each one. SQL is therefore chunked one
# statement at a time (each SELECT with the comment block above it). Only a
# statement longer than this is split further, at rule banners then blank lines.
CODE_CHUNK_SIZE = 8000
CODE_SEPARATORS = ["\n-- ====", "\n\n\n", "\n\n", "\n", ";", " ", ""]


# ============================================================================
# Helpers
# ============================================================================

def print_header(text: str) -> None:
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'=' * 60}")
    print(f"{text}")
    print(f"{'=' * 60}{Style.RESET_ALL}\n")


def print_success(text: str) -> None:
    print(f"{Fore.GREEN}[+] {text}{Style.RESET_ALL}")


def print_error(text: str) -> None:
    print(f"{Fore.RED}[!] {text}{Style.RESET_ALL}")


def print_info(text: str) -> None:
    print(f"{Fore.BLUE}[*] {text}{Style.RESET_ALL}")


# ============================================================================
# Text Splitters
# ============================================================================

def get_splitter(file_type: str):
    if file_type == "markdown":
        return MarkdownTextSplitter(
            chunk_size=DEFAULT_CHUNK_SIZE,
            chunk_overlap=DEFAULT_CHUNK_OVERLAP,
        )
    elif file_type == "code":
        return RecursiveCharacterTextSplitter(
            separators=CODE_SEPARATORS,
            chunk_size=CODE_CHUNK_SIZE,
            chunk_overlap=0,  # rule banners are natural boundaries; overlap would duplicate them
        )
    else:
        return RecursiveCharacterTextSplitter(
            chunk_size=DEFAULT_CHUNK_SIZE,
            chunk_overlap=DEFAULT_CHUNK_OVERLAP,
        )


def _file_type(filename: str) -> str | None:
    return SUPPORTED_EXTENSIONS.get(Path(filename).suffix.lower())


def _split_sql(doc: Document) -> list[Document]:
    """One chunk per top-level statement, keeping the comment block that precedes it."""
    pieces = [p.strip() for p in re.split(r"(?<=;)\n", doc.page_content)]
    pieces = [p for p in pieces if p]
    oversize = get_splitter("code")
    chunks: list[Document] = []
    for piece in pieces:
        if len(piece) > CODE_CHUNK_SIZE:
            chunks.extend(oversize.split_documents([Document(page_content=piece, metadata=dict(doc.metadata))]))
        else:
            chunks.append(Document(page_content=piece, metadata=dict(doc.metadata)))
    return chunks


def _split(docs, file_type: str) -> list:
    if file_type == "sql":
        chunks = [c for d in docs for c in _split_sql(d)]
    else:
        chunks = get_splitter(file_type).split_documents(docs)
    # Put the file name inside the text so the LLM can cite it — it only sees
    # page_content, not metadata.
    for chunk in chunks:
        name = Path(str(chunk.metadata.get("source", ""))).name
        tag = f"-- [file: {name}]" if file_type in ("sql", "code") else f"[file: {name}]"
        chunk.page_content = f"{tag}\n{chunk.page_content}"
    return chunks


# ============================================================================
# Local document loading
# ============================================================================

def load_local_documents(source_dir: Path) -> list:
    all_docs = []
    files_found = 0

    for file_path in sorted(source_dir.rglob("*")):
        if not file_path.is_file():
            continue

        ft = _file_type(file_path.name)
        if ft is None:
            continue

        files_found += 1
        try:
            loader = TextLoader(str(file_path), encoding="utf-8")
            raw_docs = loader.load()
            for doc in raw_docs:
                doc.metadata["source"] = str(file_path.relative_to(source_dir))
                doc.metadata["file_type"] = ft
            chunks = _split(raw_docs, ft)
            all_docs.extend(chunks)
            print_info(f"Loaded {len(chunks)} chunks from {file_path.name} ({ft})")
        except Exception as e:
            print_error(f"Failed to load {file_path.name}: {e}")

    if files_found == 0:
        print_error(f"No supported files found in {source_dir}")
        sys.exit(1)

    return all_docs


# ============================================================================
# GitHub document loading
# ============================================================================

def load_github_documents(repo: str, branch: str, token: str | None) -> list:
    ext_pattern = r"\.(" + "|".join(e.lstrip(".") for e in SUPPORTED_EXTENSIONS) + r")$"

    loader_kwargs = dict(
        repo=repo,
        branch=branch,
        file_filter=lambda path: bool(re.search(ext_pattern, path, re.IGNORECASE)),
    )
    if token:
        loader_kwargs["access_token"] = token

    print_info(f"Fetching files from github.com/{repo} (branch: {branch}) …")
    try:
        loader = GithubFileLoader(**loader_kwargs)
        raw_docs = loader.load()
    except Exception as e:
        print_error(f"GitHub fetch failed: {e}")
        print_error("Check that the repo exists, the branch is correct, and GITHUB_TOKEN is set if the repo is private.")
        sys.exit(1)

    if not raw_docs:
        print_error("No supported files found in the repository.")
        sys.exit(1)

    all_docs = []
    files_seen: dict[str, list] = {}
    for doc in raw_docs:
        path = doc.metadata.get("source", doc.metadata.get("path", "unknown"))
        doc.metadata["source"] = path
        ft = _file_type(path)
        if ft is None:
            continue
        doc.metadata["file_type"] = ft
        files_seen.setdefault(path, []).append(doc)

    for path, docs in sorted(files_seen.items()):
        ft = docs[0].metadata["file_type"]
        chunks = _split(docs, ft)
        all_docs.extend(chunks)
        print_info(f"Loaded {len(chunks)} chunks from {Path(path).name} ({ft})")

    return all_docs


# ============================================================================
# BigQuery document loading
# ============================================================================

def load_bigquery_documents(bq_dataset: str) -> list:
    """
    Fetch all tables from a BigQuery dataset and convert their schemas +
    sample rows into LangChain Documents for embedding.

    bq_dataset — 'project.dataset'  (e.g. bodyguard-bh2026.bodyguard_demo)
    """
    try:
        from google.cloud import bigquery as bq
    except ImportError:
        print_error("google-cloud-bigquery is not installed. Run: pip install google-cloud-bigquery")
        sys.exit(1)

    parts = bq_dataset.split(".")
    if len(parts) != 2:
        print_error("--bigquery must be in 'project.dataset' format")
        sys.exit(1)

    project, dataset = parts
    client = bq.Client(project=project)
    dataset_ref = f"{project}.{dataset}"

    print_info(f"Connecting to BigQuery dataset: {dataset_ref} …")
    try:
        tables = list(client.list_tables(dataset_ref))
    except Exception as e:
        print_error(f"BigQuery access failed: {e}")
        sys.exit(1)

    if not tables:
        print_error(f"No tables found in {dataset_ref}")
        sys.exit(1)

    all_docs = []
    splitter = get_splitter("code")

    for table_ref in tables:
        table_id = f"{project}.{dataset}.{table_ref.table_id}"
        table = client.get_table(table_id)

        # ── Schema as text ──────────────────────────────────────────────────
        schema_lines = [f"-- Table: {table_id}"]
        schema_lines.append(f"-- Description: {table.description or 'N/A'}")
        schema_lines.append("-- Schema:")
        for field in table.schema:
            schema_lines.append(f"--   {field.name}  {field.field_type}  -- {field.description or ''}")

        # ── Sample rows (up to 10) ──────────────────────────────────────────
        try:
            query = f"SELECT * FROM `{table_id}` LIMIT 10"
            rows = list(client.query(query).result())
            schema_lines.append(f"\n-- Sample data ({len(rows)} rows):")
            cols = list(rows[0].keys()) if rows else [f.name for f in table.schema]
            schema_lines.append("-- " + " | ".join(cols))
            for row in rows:
                vals = [str(v) for v in row.values()]
                schema_lines.append("-- " + " | ".join(vals))
        except Exception as e:
            schema_lines.append(f"-- (Could not fetch sample rows: {e})")

        content = "\n".join(schema_lines)
        doc = Document(
            page_content=content,
            metadata={
                "source": f"bigquery://{table_id}",
                "file_type": "code",
                "table": table_ref.table_id,
                "dataset": dataset,
                "project": project,
            },
        )
        chunks = splitter.split_documents([doc])
        all_docs.extend(chunks)
        print_info(f"Loaded {len(chunks)} chunks from BigQuery table {table_ref.table_id}")

    return all_docs


# ============================================================================
# Main Builder
# ============================================================================

def build_knowledge_base(
    output_dir: Path,
    force: bool,
    ollama_host: str,
    embed_model: str,
    source_dir: Path | None = None,
    github_repo: str | None = None,
    github_branch: str = "main",
    github_token: str | None = None,
    bigquery_dataset: str | None = None,
) -> None:
    print_header("Bodyguard — Knowledge Base Builder")

    if output_dir.exists() and any(output_dir.iterdir()):
        if not force:
            print_error(
                f"Output directory {output_dir} already contains data. "
                "Use --force to overwrite."
            )
            sys.exit(1)
        print_info("Overwriting existing vector store (--force).")

    output_dir.mkdir(parents=True, exist_ok=True)

    if bigquery_dataset:
        docs = load_bigquery_documents(bigquery_dataset)
    elif github_repo:
        docs = load_github_documents(github_repo, github_branch, github_token)
    else:
        if not source_dir or not source_dir.exists():
            print_error(f"Source directory not found: {source_dir}")
            sys.exit(1)
        print_info(f"Loading documents from: {source_dir}")
        docs = load_local_documents(source_dir)

    print_success(f"Loaded {len(docs)} total chunks")

    print_info(f"Embedding with {embed_model} via Ollama at {ollama_host} …")
    try:
        embeddings = OllamaEmbeddings(model=embed_model, base_url=ollama_host)
        vector_store = FAISS.from_documents(docs, embeddings)
    except Exception as e:
        print_error(f"Embedding failed: {e}")
        sys.exit(1)

    vector_store.save_local(str(output_dir))
    print_success(f"FAISS index saved to: {output_dir}")
    print_success("Knowledge base built. Run main.py or python -m web.app to query it.")


# ============================================================================
# CLI
# ============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build a FAISS knowledge base from a local directory, a GitHub repo, or a BigQuery dataset.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m kb.builder --source test/demo --output vector_store
  python -m kb.builder --github owner/security-rules --output vector_store
  python -m kb.builder --github myorg/repo --branch develop --output vector_store --force
  python -m kb.builder --bigquery myproject.bodyguard_demo --output vector_store --force
        """,
    )

    source_group = parser.add_mutually_exclusive_group(required=False)
    source_group.add_argument("--source", type=Path, help="Local directory to ingest")
    source_group.add_argument("--github", metavar="OWNER/REPO", help="GitHub repo to ingest")
    source_group.add_argument("--bigquery", metavar="PROJECT.DATASET",
                              help="BigQuery dataset to ingest (e.g. bodyguard-bh2026.bodyguard_demo)")

    parser.add_argument("--branch", default="main", help="GitHub branch (default: main)")
    parser.add_argument("--output", type=Path, default=Path("vector_store"),
                        help="FAISS output directory (default: vector_store)")
    parser.add_argument("--force", action="store_true", help="Overwrite existing vector store")
    parser.add_argument("--ollama-host", default=DEFAULT_OLLAMA_HOST)
    parser.add_argument("--embed-model", default=DEFAULT_EMBED_MODEL)

    args = parser.parse_args()
    source_dir = args.source or (Path("test/demo") if not args.github and not args.bigquery else None)

    build_knowledge_base(
        output_dir=args.output,
        force=args.force,
        ollama_host=args.ollama_host,
        embed_model=args.embed_model,
        source_dir=source_dir,
        github_repo=args.github,
        github_branch=args.branch,
        github_token=os.getenv("GITHUB_TOKEN"),
        bigquery_dataset=args.bigquery,
    )


if __name__ == "__main__":
    main()
