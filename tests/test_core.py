"""Unit tests that need no Ollama, no FAISS index, and no network."""

from pathlib import Path

import pytest

from agent import core


def test_prompt_loads_and_concatenates_redteam(tmp_path: Path):
    prompt = tmp_path / "prompts.md"
    redteam = tmp_path / "REDTEAM.md"
    prompt.write_text("# System\nBe terse.")
    redteam.write_text("## Red Team\n- 10.0.0.0/8")

    result = core.load_system_prompt(prompt, redteam)

    assert result.startswith("# System")
    assert "\n\n---\n\n## Red Team" in result


def test_prompt_without_redteam_file(tmp_path: Path):
    prompt = tmp_path / "prompts.md"
    prompt.write_text("# System")

    result = core.load_system_prompt(prompt, tmp_path / "missing.md")

    assert result == "# System"


def test_missing_prompt_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        core.load_system_prompt(tmp_path / "nope.md", tmp_path / "REDTEAM.md")


def test_shipped_prompt_is_loadable():
    """The real prompts.md must exist and mention the REDTEAM.md mechanism."""
    text = core.load_system_prompt()
    assert "Bodyguard" in text
    assert "REDTEAM.md" in text


def test_sources_dedup_preserves_order():
    class Doc:
        def __init__(self, source):
            self.metadata = {"source": source}

    docs = [Doc("phishing.sql"), Doc("docs/algo.md"), Doc("phishing.sql"), Doc("urls_30d.sql")]
    assert core._sources(docs) == ["phishing.sql", "docs/algo.md", "urls_30d.sql"]


def test_missing_vector_store_message_points_to_kb_builder(tmp_path: Path):
    with pytest.raises(FileNotFoundError, match="kb.builder"):
        core.load_agent(vector_store_path=tmp_path / "missing")
