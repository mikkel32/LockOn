"""
Action Enforcer - Execute security actions and countermeasures
"""
from pathlib import Path
from typing import Optional

from utils.logger import SecurityLogger


class ActionEnforcer:
    """Simplified security action handler used for tests"""

    def __init__(self):
        self.logger = SecurityLogger()
        self.active_protection = False

    def enable_active_protection(self):
        self.active_protection = True
        self.logger.info("Active protection enabled")

    def disable_active_protection(self):
        self.active_protection = False
        self.logger.info("Active protection disabled")

    # Placeholder methods used by FolderMonitor
    def quarantine_file(self, filepath: Path):
        self.logger.warning(f"Quarantine file: {filepath}")

    def restore_file(self, filepath: Path):
        self.logger.info(f"Restore file: {filepath}")

    def emergency_lockdown(self, folder: Optional[Path]):
        self.logger.critical(f"Emergency lockdown triggered on {folder}")

    def emergency_backup(self, folder: Optional[Path]):
        self.logger.info(f"Emergency backup for {folder}")

    def block_file_access(self, filepath: Path):
        self.logger.info(f"Block access to {filepath}")

    def restrict_permissions(self, filepath: Path):
        self.logger.info(f"Restrict permissions on {filepath}")

    def handle_suspicious_process(self, process):
        try:
            proc_name = process.name()
        except Exception:
            proc_name = str(process)
        self.logger.warning(f"Handle suspicious process: {proc_name}")
