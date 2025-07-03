from __future__ import annotations

import os
from pathlib import Path
from .paths import resource_path
import yaml

CONFIG_ENV = "LOCKON_CONFIG"
CONFIG_PATH = resource_path(*Path(os.environ.get(CONFIG_ENV, "config.yaml")).parts)


def ensure_config(path: Path = CONFIG_PATH) -> None:
    """Create a default configuration file if it does not exist."""
    if path.exists():
        return
    sample = {
        "logging": {"file": "data/logs/app.log", "level": "INFO"},
        "monitor": {"paths": ["."], "recursive": True},
        "database": {"path": "data/database.db"},
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(sample))


def load_config(path: Path | None = None) -> dict:
    """Load YAML configuration as a dictionary."""
    final = Path(os.environ.get(CONFIG_ENV, str(path or CONFIG_PATH))).expanduser()
    if not final.exists():
        return {}
    with open(final) as f:
        return yaml.safe_load(f) or {}


class Config(dict):
    """Simple wrapper to provide attribute-style access."""

    def __init__(self, path: Path | None = None):
        final = Path(os.environ.get(CONFIG_ENV, str(path or CONFIG_PATH))).expanduser()
        super().__init__(load_config(final))
        self.path = final

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(yaml.safe_dump(dict(self)))
