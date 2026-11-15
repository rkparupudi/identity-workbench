"""Runtime settings, read from environment variables (and an optional .env file)."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _load_dotenv() -> None:
    """Minimal .env loader so there is no extra dependency. Existing env vars win."""
    path = Path.cwd() / ".env"
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key and value and key not in os.environ:
            os.environ[key] = value


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    home: Path
    data_dir: Path
    model: str
    api_key: str
    match_upper: int
    match_lower: int
    dormant_days: int

    @property
    def db_path(self) -> Path:
        return self.home / "workbench.db"


def get_settings() -> Settings:
    _load_dotenv()
    home = Path(os.environ.get("IDW_HOME") or Path.home() / ".identity-workbench")
    home.mkdir(parents=True, exist_ok=True)
    data_dir = Path(os.environ.get("IDW_DATA_DIR") or Path.cwd()).resolve()
    return Settings(
        home=home,
        data_dir=data_dir,
        model=os.environ.get("IDW_MODEL") or "claude-sonnet-5-5",
        api_key=os.environ.get("ANTHROPIC_API_KEY", ""),
        match_upper=_int("IDW_MATCH_UPPER", 90),
        match_lower=_int("IDW_MATCH_LOWER", 70),
        dormant_days=_int("IDW_DORMANT_DAYS", 90),
    )
