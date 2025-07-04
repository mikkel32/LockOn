"""
Action Enforcer - Execute security actions and countermeasures
"""
from pathlib import Path
from typing import Optional

from utils.logger import SecurityLogger
from security.quarantine import QuarantineManager
from security.privileges import PrivilegeManager, require_privileges


class ActionEnforcer:
    """Simplified security action handler used for tests"""

    def __init__(self, quarantine_dir: Path | None = None, priv_manager: PrivilegeManager | None = None):
        self.logger = SecurityLogger()
        self.active_protection = False
        self.priv_manager = priv_manager or PrivilegeManager(auto_acquire=False)
        self.quarantine_manager = QuarantineManager(
            quarantine_dir or QuarantineManager.QUARANTINE_DIR,
            priv_manager=self.priv_manager,
        )


    def enable_active_protection(self):
        self.active_protection = True
        self.logger.info("Active protection enabled")

    def disable_active_protection(self):
        self.active_protection = False
        self.logger.info("Active protection disabled")

    # Placeholder methods used by FolderMonitor
    @require_privileges(["SeBackupPrivilege"])
    def quarantine_file(self, filepath: Path):
        qpath = self.quarantine_manager.quarantine(str(filepath))
        self.logger.warning(f"Quarantine file: {filepath} -> {qpath}")

    @require_privileges(["SeRestorePrivilege"])
    def restore_file(self, filepath: Path):
        qfile = self.quarantine_manager.directory / filepath.name
        if qfile.exists():
            restored = self.quarantine_manager.restore(str(qfile), filepath)
        else:
            restored = filepath
        self.logger.info(f"Restore file: {restored}")

    @require_privileges(["SeShutdownPrivilege"])
    def emergency_lockdown(self, folder: Optional[Path]):
        self.logger.critical(f"Emergency lockdown triggered on {folder}")

    @require_privileges(["SeBackupPrivilege"])
    def emergency_backup(self, folder: Optional[Path]):
        self.logger.info(f"Emergency backup for {folder}")

    @require_privileges(["SeSecurityPrivilege"])
    def block_file_access(self, filepath: Path):
        self.logger.info(f"Block access to {filepath}")

    @require_privileges(["SeSecurityPrivilege"])
    def restrict_permissions(self, filepath: Path):
        self.logger.info(f"Restrict permissions on {filepath}")

    @require_privileges(["SeDebugPrivilege"])
    def handle_suspicious_process(self, process):
        try:
            proc_name = process.name()
        except Exception:
            proc_name = str(process)
        self.logger.warning(f"Handle suspicious process: {proc_name}")
