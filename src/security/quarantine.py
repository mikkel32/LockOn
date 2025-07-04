from pathlib import Path
import shutil
from datetime import datetime

from utils.paths import resource_path
from utils.logger import logger
from security.privileges import PrivilegeManager, require_privileges

QUARANTINE_DIR = resource_path("data", "quarantine")


class QuarantineManager:
    """Handle quarantined files."""

    QUARANTINE_DIR = QUARANTINE_DIR

    def __init__(self, directory: Path = QUARANTINE_DIR, priv_manager: PrivilegeManager | None = None):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.priv_manager = priv_manager or PrivilegeManager()

    @require_privileges(["SeBackupPrivilege"])
    def quarantine(self, path: str) -> Path:
        """Move *path* into the quarantine directory and return the new path."""
        src = Path(path)
        target = self.directory / src.name
        if target.exists():
            suffix = datetime.now().strftime("%Y%m%d%H%M%S")
            target = target.with_name(f"{target.stem}_{suffix}{target.suffix}")
        try:
            shutil.move(str(src), target)
        except Exception as exc:
            logger.error(f"Failed to quarantine {src}: {exc}")
            raise
        return target

    @require_privileges(["SeRestorePrivilege"])
    def restore(self, quarantined: str, dest: Path | None = None) -> Path:
        """Restore *quarantined* file back to *dest* or its original location."""
        q = Path(quarantined)
        destination = Path(dest or q.name)
        try:
            shutil.move(str(q), str(destination))
        except Exception as exc:
            logger.error(f"Failed to restore {quarantined}: {exc}")
            raise
        return destination
