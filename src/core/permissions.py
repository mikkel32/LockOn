"""Permission Manager - simple permission checks for tests"""
from pathlib import Path
from typing import List


class PermissionManager:
    def __init__(self):
        self.file_permissions = {
            'blocked_extensions': {'.exe', '.dll', '.bat', '.cmd', '.scr'},
        }
        self.process_permissions = {
            'whitelist': {'python.exe', 'explorer.exe', 'chrome.exe'},
            'blacklist': set(),
        }

    def check_file_permission(self, filepath: Path, operation: str) -> bool:
        """Return True if file operation is allowed."""
        ext = filepath.suffix.lower()
        if ext in self.file_permissions['blocked_extensions']:
            return False
        return True

    def check_process_permission(self, process_name: str, operation: str) -> bool:
        """Return True if process is permitted to execute."""
        name = process_name.lower()
        if name in self.process_permissions['blacklist']:
            return False
        if self.process_permissions['whitelist'] and name not in self.process_permissions['whitelist']:
            return False
        return True

    def update_blacklist(self, process_names: List[str], add: bool = True):
        for name in process_names:
            name = name.lower()
            if add:
                self.process_permissions['blacklist'].add(name)
            else:
                self.process_permissions['blacklist'].discard(name)

    def update_whitelist(self, process_names: List[str], add: bool = True):
        for name in process_names:
            name = name.lower()
            if add:
                self.process_permissions['whitelist'].add(name)
            else:
                self.process_permissions['whitelist'].discard(name)
