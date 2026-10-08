#!/usr/bin/env python3
"""
Bodyguard — Local CLI

Interactive terminal session to query the security knowledge base.

Usage:
    python main.py
    python main.py --ollama-host http://my-server:11434 --llm llama3
"""

import argparse
import os
import sys
from pathlib import Path

from colorama import Fore, Style, init

from agent.core import ask, load_agent

init(autoreset=True)

BANNER = f"""
{Fore.CYAN}{Style.BRIGHT}
  ██████   ██████  ██████  ██    ██  ██████   ██    ██  █████  ██████  ██████
  ██   ██ ██    ██ ██   ██  ██  ██  ██        ██    ██ ██   ██ ██   ██ ██   ██
  ██████  ██    ██ ██   ██   ████   ██   ███  ██    ██ ███████ ██████  ██   ██
  ██   ██ ██    ██ ██   ██    ██    ██    ██  ██    ██ ██   ██ ██   ██ ██   ██
  ██████   ██████  ██████     ██     ██████    ██████  ██   ██ ██   ██ ██████
{Style.RESET_ALL}
{Fore.YELLOW}  Who is my Bodyguard? — AI security knowledge assistant{Style.RESET_ALL}
  Type your question and press Enter. Type {Fore.RED}exit{Style.RESET_ALL} or Ctrl-C to quit.
"""

SAMPLE_QUESTIONS = [
    "How does our phishing protection work? Give me a concrete example with a URL.",
    "Show me the code that detects SQL injection.",
    "Is 198.51.100.50 an attacker? Should the SOC be worried?",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Bodyguard security agent CLI")
    parser.add_argument("--ollama-host", default=os.getenv("OLLAMA_HOST", "http://localhost:11434"))
    parser.add_argument("--embed-model", default=os.getenv("EMBED_MODEL", "jina/jina-embeddings-v2-base-en"))
    parser.add_argument("--llm", default=os.getenv("LLM_MODEL", "llama3.2"))
    parser.add_argument("--vector-store", type=Path, default=Path(os.getenv("VECTOR_STORE", "vector_store")))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    print(BANNER)

    print(f"{Fore.BLUE}[*] Loading knowledge base from '{args.vector_store}'...{Style.RESET_ALL}")
    try:
        agent = load_agent(
            vector_store_path=args.vector_store,
            ollama_host=args.ollama_host,
            embed_model=args.embed_model,
            llm_model=args.llm,
        )
    except FileNotFoundError as exc:
        print(f"{Fore.RED}[!] {exc}{Style.RESET_ALL}")
        sys.exit(1)

    print(f"{Fore.GREEN}[+] Ready. Try one of these:  {Style.RESET_ALL}")
    for q in SAMPLE_QUESTIONS:
        print(f"    {Fore.YELLOW}• {q}{Style.RESET_ALL}")
    print()

    while True:
        try:
            question = input(f"{Fore.CYAN}You >{Style.RESET_ALL} ").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{Fore.YELLOW}Goodbye.{Style.RESET_ALL}")
            break

        if not question:
            continue
        if question.lower() in {"exit", "quit", "q"}:
            print(f"{Fore.YELLOW}Goodbye.{Style.RESET_ALL}")
            break

        print(f"{Fore.BLUE}[*] Thinking...{Style.RESET_ALL}\n")
        result = ask(agent, question)

        print(f"{Fore.GREEN}Bodyguard >{Style.RESET_ALL}")
        print(result["answer"])

        if result["sources"]:
            print(f"\n{Fore.YELLOW}Sources: {', '.join(result['sources'])}{Style.RESET_ALL}")
        print()


if __name__ == "__main__":
    main()
