from pathlib import Path
import yaml

CONFIG_PATH = Path("config.yaml")


def load_config(path: Path = CONFIG_PATH):
    """Load YAML configuration as a dictionary."""
    if not path.exists():
        return {}
    with open(path) as f:
        return yaml.safe_load(f) or {}


class Config(dict):
    """Simple wrapper to provide attribute-style access."""

    def __init__(self, path: Path = CONFIG_PATH):
        super().__init__(load_config(path))
        self.path = path

    def save(self) -> None:
        self.path.write_text(yaml.safe_dump(dict(self)))
