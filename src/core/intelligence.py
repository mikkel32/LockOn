import json
from pathlib import Path

INTELLIGENCE_DIR = Path("Intelligence")


class Intelligence:
    def __init__(self):
        self.patterns = self._load_json("patterns.json")
        self.rules = self._load_json("rules.json")
        self.behaviors = self._load_json("behaviors.json")
        self.responses = self._load_json("responses.json")

    def _load_json(self, name: str):
        path = INTELLIGENCE_DIR / name
        if path.exists():
            with open(path) as f:
                return json.load(f)
        return {}
