import logging
from pathlib import Path
from typing import List

try:
    import yara  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    yara = None

logger = logging.getLogger("LockOn")


class YaraScanner:
    """Wrapper around yara to scan files for malware patterns."""

    def __init__(self, rules_path: Path | str | None = None) -> None:
        self.rules = None
        self.threat_map: dict[str, str] = {}
        if rules_path:
            self.rules_path = Path(rules_path)
        else:
            from utils.paths import resource_path
            self.rules_path = resource_path("Intelligence", "yara_rules.yar")
        self._mtime = 0.0
        self._load_rules()

    def _load_rules(self) -> None:
        """Compile rules and build the threat map."""
        if yara is None:  # pragma: no cover - yara not installed
            logger.debug("yara-python not available, YARA scanning disabled")
            return
        if not self.rules_path.exists():
            logger.warning("YARA rules file %s not found", self.rules_path)
            return
        try:
            self.rules = yara.compile(filepath=str(self.rules_path))
            self._mtime = self.rules_path.stat().st_mtime
            self.threat_map = {}
            for r in self.rules:
                threat = r.meta.get("threat") if hasattr(r, "meta") else None
                if threat:
                    self.threat_map[r.identifier.lower()] = str(threat).lower()
        except Exception as exc:  # pragma: no cover - invalid rules
            logger.warning("Failed to compile YARA rules: %s", exc)
            self.rules = None

    def reload_if_updated(self) -> None:
        """Reload YARA rules if the file changed."""
        if yara is None or not self.rules_path.exists():
            return
        try:
            mtime = self.rules_path.stat().st_mtime
        except OSError:
            return
        if mtime != self._mtime:
            self._load_rules()

    def scan_file(self, filepath: Path) -> List[str]:
        """Return list of matching rule names for *filepath*."""
        self.reload_if_updated()
        if not self.rules:
            return []
        try:
            matches = self.rules.match(str(filepath))
            return [m.rule for m in matches]
        except Exception as exc:  # pragma: no cover - scan error
            logger.warning("YARA scan error on %s: %s", filepath, exc)
            return []

    def scan_file_meta(self, filepath: Path) -> List[tuple[str, dict]]:
        """Return list of (rule name, meta) tuples for *filepath*."""
        self.reload_if_updated()
        if not self.rules:
            return []
        try:
            matches = self.rules.match(str(filepath))
            return [(m.rule, m.meta) for m in matches]
        except Exception as exc:
            logger.warning("YARA scan error on %s: %s", filepath, exc)
            return []

    def scan_bytes(self, data: bytes) -> List[str]:
        """Return list of matching rule names for in-memory *data*."""
        self.reload_if_updated()
        if not self.rules:
            return []
        try:
            matches = self.rules.match(data=data)
            return [m.rule for m in matches]
        except Exception as exc:  # pragma: no cover - scan error
            logger.warning("YARA scan error on bytes: %s", exc)
            return []

    def scan_bytes_meta(self, data: bytes) -> List[tuple[str, dict]]:
        """Return list of (rule name, meta) tuples for in-memory *data*."""
        self.reload_if_updated()
        if not self.rules:
            return []
        try:
            matches = self.rules.match(data=data)
            return [(m.rule, m.meta) for m in matches]
        except Exception as exc:
            logger.warning("YARA scan error on bytes: %s", exc)
            return []
