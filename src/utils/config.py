from pathlib import Path
import yaml

CONFIG_PATH = Path("config.yaml")


def load_config(path: Path = CONFIG_PATH):
    if not path.exists():
        return {}
    with open(path) as f:
        return yaml.safe_load(f) or {}
