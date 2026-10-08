---
name: Bug report
about: Report something that isn't working as expected
title: ''
labels: bug
assignees: ''
---

**Describe the bug**
A clear and concise description of what the bug is.

**To reproduce**
How the knowledge base was built (`make build`, `make build-github REPO=...`,
`make build-bq DATASET=...`), which interface you used (web, CLI, Slack, REST),
and the exact question you asked.

```
Question:
```

**Expected behavior**
What you expected to happen instead.

**Actual output / traceback**
```
Paste the answer you got, or the full traceback.
```

**Retrieval diagnostics**
If the agent cited a file that doesn't exist, missed a rule, or answered from
the wrong source, please check retrieval first — in this project that has been
the cause every time. Run this against your `vector_store` with the question
that failed and paste the output:

```python
from langchain_community.vectorstores import FAISS
from langchain_ollama import OllamaEmbeddings
from agent.core import HybridRetriever

vs = FAISS.load_local(
    "vector_store",
    OllamaEmbeddings(model="jina/jina-embeddings-v2-base-en"),
    allow_dangerous_deserialization=True,
)
for d in HybridRetriever(vs).invoke("<your question here>"):
    print(d.metadata["source"], d.page_content[:80])
```

```
Paste the retrieved chunks here.
```

**Environment**
- Bodyguard commit or release:
- LLM model (`LLM_MODEL`, default `llama3.2`):
- Embedding model (default `jina/jina-embeddings-v2-base-en`):
- Ollama version:
- Python version:
- OS:
- Running in Docker: yes / no

**Additional context**
Anything else that might help. Note that some questions are known to be
unreliable on a 3B model — triage verdicts, "not in the knowledge base"
refusals, and cross-topic gap analysis need 8B+. The README's use-case table
says which.
