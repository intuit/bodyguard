# Contributing to Bodyguard

Thanks for your interest in contributing. Whether it's improving documentation,
fixing a bug, or proposing a feature, contributions are welcome.

- [Reporting bugs and requesting features](#reporting-bugs-and-requesting-features)
- [Development setup](#development-setup)
- [Working on the demo knowledge base](#working-on-the-demo-knowledge-base)
- [Code quality expectations](#code-quality-expectations)
- [Contribution process](#contribution-process)
- [AI-assisted contributions](#ai-assisted-contributions)
- [Contact](#contact)

## Reporting bugs and requesting features

Please open a [GitHub issue](https://github.com/intuit/bodyguard/issues/new/choose)
using the bug report or feature request template.

For bug reports, include as much detail as you can: your Python version and OS,
the Ollama model you are using (`LLM_MODEL`), how the knowledge base was built
(`make build`, `--github`, or `--bigquery`), the question you asked, and the
answer you got.

Before filing a retrieval bug ("the agent invented a file", "the agent missed
the SQLi rule"), check what was actually retrieved — in this project that has
been the cause every time:

```python
from langchain_community.vectorstores import FAISS
from langchain_ollama import OllamaEmbeddings
from agent.core import HybridRetriever

vs = FAISS.load_local(
    "vector_store",
    OllamaEmbeddings(model="jina/jina-embeddings-v2-base-en"),
    allow_dangerous_deserialization=True,
)
for d in HybridRetriever(vs).invoke("Show me the code that detects SQL injection."):
    print(d.metadata["source"], d.page_content[:80])
```

Paste that output into the issue. If the target chunk is missing, it is a
retrieval or chunking bug; if it is present and the answer is still wrong, say
which model you ran — some questions are known to need an 8B+ model (see the
use-case table in the README).

Please do not report security vulnerabilities through public GitHub issues.
Follow [Intuit's responsible disclosure process](https://www.intuit.com/privacy/report-vulnerability/)
instead.

## Development setup

You need Python 3.10 or newer and a running [Ollama](https://ollama.com)
instance. macOS's Xcode `python3` is 3.9 and will be rejected; override the
interpreter with `SYSTEM_PYTHON=` if needed.

```bash
git clone https://github.com/intuit/bodyguard.git
cd bodyguard

make setup-dev                    # venv + runtime deps + pytest + matplotlib
# make setup-dev SYSTEM_PYTHON=/path/to/python3.12   # if auto-detection picks the wrong one

ollama pull llama3.2
ollama pull jina/jina-embeddings-v2-base-en

make build                        # build the demo knowledge base from test/demo
make run                          # web app on http://localhost:5001
```

Other entry points: `make cli` (interactive CLI) and `make slack` (Socket Mode
bot). `make help` lists every target.

Run the tests:

```bash
make test                         # pytest; no Ollama or BigQuery needed
```

The BigQuery demo dataset is optional and only needed if you are changing
`scripts/deploy_bq.py` or the schema files:

```bash
make check-demo                   # offline: schema files are well-formed
make deploy-bq                    # (re)create the demo tables, then run every rule
```

## Working on the demo knowledge base

`test/demo/` is a deliberately constructed demo, not an example of good
practice. Two rules protect it:

1. **The runbooks in `test/demo/security-wiki/` disagree with the code in
   `test/demo/detection-rules/` on purpose.** Mismatched table names, a
   threshold of 50 versus 100, rules described in the docs that do not exist in
   the SQL — these are the "theory versus reality" demo and the README's use
   cases depend on them. Do not "fix" them. If you change one side, update the
   README use-case table so it stays honest.

2. **Data conventions are enforced by `tests/test_bq_demo.py`.** IP addresses
   must come from the RFC 5737 documentation ranges, ASNs from the RFC 5398
   documentation range with fictional operator names. Never end a comment line
   with `;` — both `kb/builder.py` and `scripts/deploy_bq.py` split SQL
   statements on it. The schema files under
   `test/demo/detection-rules/schema/` are the only source of truth for the
   demo rows; never hand-edit rows in `scripts/deploy_bq.py`.

Contributions must not add organization-specific data: no real IP ranges, no
internal hostnames, no proprietary schemas, no employer-specific references.
`agent/prompts.md` and `REDTEAM.md` ship with generic examples only.

Two more things that are easy to get wrong:

- **`agent/prompts.md` and `REDTEAM.md` are sent to the model verbatim.** They
  are not documentation. Human-facing guidance ("how to customise this")
  belongs in the README; anything you put in a prompt file, a small model will
  recite back to users. Editing them requires an app restart, not a KB rebuild.
- **Do not "simplify away" `num_ctx=16384` or `ChatOllama` in `agent/core.py`.**
  Ollama's default context is 2048 tokens and the system prompt alone is about
  2000, so the prompt gets silently truncated; `OllamaLLM` is the completion
  endpoint and has no system role. Both were real bugs.

## Code quality expectations

There is no enforced formatter or linter on this repository. Match the style of
the file you are editing: 4-space indentation, type hints where the surrounding
code uses them, and comments that explain *why* rather than restate *what*.

- **Tests** — new features and bug fixes should come with tests. A bug fix
  should include a test that fails before the fix and passes after it.
  `make test` must pass, and it must keep passing without Ollama, network
  access, or BigQuery credentials.
- **Documentation** — user-facing changes belong in the `README.md`. Changes to
  architecture, retrieval settings, chunking, or the demo KB belong in
  `CLAUDE.md` as well, which is the maintainers' working notes.
- **Dependencies** — adding one needs a reason in the pull request description.
  Runtime dependencies go in `requirements.txt`, development-only ones in
  `requirements-dev.txt`. The web UI is deliberately vanilla with no CDN.

## Contribution process

Contributions are made through a fork and pull request.

1. Fork the repository on GitHub, then clone your fork and add the upstream
   remote:

   ```bash
   git clone git@github.com:<your-username>/bodyguard.git
   cd bodyguard
   git remote add upstream https://github.com/intuit/bodyguard.git
   ```

2. Create a branch with a descriptive name:

   ```bash
   git checkout -b fix/bm25-tokenizer
   ```

3. Make your changes, including tests and documentation. Write commit messages
   that describe what changed and why.

4. Keep your branch current with rebase rather than merge:

   ```bash
   git fetch upstream
   git rebase upstream/main
   git push origin <your-branch>
   ```

5. Open a pull request against `main` and fill out the template. Link the
   issue it addresses (e.g. `Closes #123`). For anything that changes
   retrieval, chunking, or the prompt, the template asks for before/after
   output for the affected questions — on this project a prompt tweak that
   fixes one question routinely breaks another.

A maintainer will review your change and may suggest adjustments.

## AI-assisted contributions

If you use Claude Code, [`CLAUDE.md`](CLAUDE.md) at the repository root carries
the architecture, the build and test commands, the reasoning behind the
retrieval and chunking settings, and the field notes on failures that have
already cost someone an hour. Read it before re-deriving any of them.

AI-assisted contributions are welcome, but you are responsible for the code you
submit: review it, test it, and be able to explain it in review.

## Contact

The best place to reach the maintainers is a GitHub issue. Current maintainers
are listed in [.github/CODEOWNERS](.github/CODEOWNERS).

By contributing, you agree that your contributions will be licensed under the
[MIT License](LICENSE), and that you will abide by the
[Code of Conduct](CODE_OF_CONDUCT.md).
