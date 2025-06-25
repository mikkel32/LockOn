from pathlib import Path
import shutil

QUARANTINE_DIR = Path("data/quarantine")


class QuarantineManager:
    def __init__(self, directory: Path = QUARANTINE_DIR):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def quarantine(self, path: str) -> Path:
        target = self.directory / Path(path).name
        shutil.move(path, target)
        return target
