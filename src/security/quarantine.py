from pathlib import Path
import shutil

QUARANTINE_DIR = Path("data/quarantine")


class QuarantineManager:
    """Handle quarantined files."""

    QUARANTINE_DIR = QUARANTINE_DIR

    def __init__(self, directory: Path = QUARANTINE_DIR):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def quarantine(self, path: str) -> Path:
        """Move *path* into the quarantine directory and return the new path."""
        target = self.directory / Path(path).name
        shutil.move(path, target)
        return target

    def restore(self, quarantined: str, dest: Path | None = None) -> Path:
        """Restore *quarantined* file back to *dest* or its original location."""
        q = Path(quarantined)
        destination = Path(dest or q.name)
        shutil.move(q, destination)
        return destination
