import json
from datetime import date

import pytest

from workbench.core.store import Store
from workbench.synth.generate import generate


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Every test gets its own store and data folder; no model calls."""
    monkeypatch.setenv("IDW_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("IDW_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.chdir(tmp_path)


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "home" / "workbench.db")


@pytest.fixture
def dataset(tmp_path):
    folder = tmp_path / "data"
    generate(folder, employees=400, seed=5, as_of=date(2026, 11, 1))
    truth = json.loads((folder / "truth.json").read_text())
    return folder, truth
