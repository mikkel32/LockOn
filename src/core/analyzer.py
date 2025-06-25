from src.utils.logger import logger
from .intelligence import Intelligence


class Analyzer:
    def __init__(self, intelligence: Intelligence):
        self.intelligence = intelligence

    def analyze(self, event) -> bool:
        return any(
            event.src_path.endswith(ext)
            for ext in self.intelligence.patterns.get("suspicious_extensions", [])
        )
