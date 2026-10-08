PYTHON   := .venv/bin/python
PIP      := .venv/bin/pip
VENV     := .venv

# Interpreter used to create the venv. Prefers a modern python3.x if several
# are installed (macOS ships an old python3 with Xcode). Override with:
#   make setup SYSTEM_PYTHON=/path/to/python3.12
SYSTEM_PYTHON ?= $(shell for p in python3.13 python3.12 python3.11 python3.10 python3; do command -v $$p && break; done)

# ── Setup ──────────────────────────────────────────────────────────────────────

.PHONY: setup
setup:
	@test -n "$(SYSTEM_PYTHON)" || (echo "No python3 found. Install Python 3.10+ first." && exit 1)
	@$(SYSTEM_PYTHON) -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' \
		|| (echo "Python 3.10+ required, found: $$($(SYSTEM_PYTHON) --version). Set SYSTEM_PYTHON=/path/to/python3.x" && exit 1)
	@echo "Using $$($(SYSTEM_PYTHON) --version) at $(SYSTEM_PYTHON)"
	$(SYSTEM_PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	@echo ""
	@echo "Setup complete. Run 'make build' then 'make run'."

.PHONY: setup-dev
setup-dev: setup
	$(PIP) install -r requirements-dev.txt

.PHONY: test
test:
	$(PYTHON) -m pytest tests -q

# ── Knowledge Base ─────────────────────────────────────────────────────────────

.PHONY: build
build:
	$(PYTHON) -m kb.builder --source test/demo --output vector_store --force

.PHONY: build-github
build-github:
	@test -n "$(REPO)" || (echo "Usage: make build-github REPO=owner/repo" && exit 1)
	GITHUB_TOKEN=$$(gh auth token 2>/dev/null) \
	$(PYTHON) -m kb.builder --github $(REPO) --output vector_store --force

.PHONY: build-bq
build-bq:
	@test -n "$(DATASET)" || (echo "Usage: make build-bq DATASET=project.dataset" && exit 1)
	$(PYTHON) -m kb.builder --bigquery $(DATASET) --output vector_store --force

# ── Run ───────────────────────────────────────────────────────────────────────

.PHONY: run
run:
	$(PYTHON) -m web.app

.PHONY: cli
cli:
	$(PYTHON) main.py

.PHONY: slack
slack:
	$(PYTHON) -m slack.bot

# ── BigQuery demo dataset ──────────────────────────────────────────────────────

.PHONY: deploy-bq
deploy-bq:                       # create + fill the 4 demo tables from test/demo/detection-rules/schema, then run every rule
	$(PYTHON) scripts/deploy_bq.py --verify

.PHONY: verify-bq
verify-bq:                       # run every detection rule against BigQuery and print row counts
	$(PYTHON) scripts/deploy_bq.py --verify-only

.PHONY: check-demo
check-demo:                      # offline: schema files are well-formed (column count vs row arity)
	$(PYTHON) scripts/deploy_bq.py --check

# ── Diagram ───────────────────────────────────────────────────────────────────

.PHONY: diagram
diagram:
	$(PYTHON) static/gen_diagram.py

# ── Help ──────────────────────────────────────────────────────────────────────

.PHONY: help
help:
	@echo "Bodyguard — available targets:"
	@echo ""
	@echo "  make setup              Create virtualenv and install dependencies"
	@echo "  make setup-dev          Same, plus pytest and matplotlib"
	@echo "  make test               Run the unit tests"
	@echo "  make build              Build vector store from test/demo (default)"
	@echo "  make build-github REPO=owner/repo   Build from a GitHub repo"
	@echo "  make build-bq DATASET=project.ds    Build from a BigQuery dataset"
	@echo "  make run                Start the web app  (http://localhost:5001)"
	@echo "  make cli                Start the interactive CLI"
	@echo "  make slack              Start the Slack bot"
	@echo "  make deploy-bq          Deploy demo tables to BigQuery"
	@echo "  make diagram            Regenerate static/architecture.png"
