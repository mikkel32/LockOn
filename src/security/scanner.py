"""File scanning utilities leveraging hashing and YARA signatures."""

from pathlib import Path
from typing import Dict, List, Tuple

from utils.logger import logger
from utils.paths import resource_path
from .hasher import file_hash

try:  # pragma: no cover - optional dependency
    from .yara_scanner import YaraScanner
except Exception:  # pragma: no cover - yara not available
    YaraScanner = None


class Scanner:
    """High-level scanner that hashes and checks files with YARA."""

    def __init__(self, yara_scanner: "YaraScanner | None" = None) -> None:
        self.yara = yara_scanner
        if self.yara is None and YaraScanner is not None:
            rules = resource_path("Intelligence", "yara_rules.yar")
            self.yara = YaraScanner(rules)
        self._cache: Dict[str, Tuple[str, float, List[str], List[tuple[str, dict]]]] = {}

    def scan(self, path: str) -> Dict[str, List[str] | str | List[tuple[str, dict]]]:
        """Return hash, YARA matches and metadata for *path*."""
        fp = Path(path)
        try:
            mtime = fp.stat().st_mtime
        except Exception:
            return {"hash": "", "yara": []}

        cached = self._cache.get(path)
        if cached and cached[1] == mtime:
            digest, _, matches, meta = cached
        else:
            digest = file_hash(path)
            matches: List[str] = []
            meta: List[tuple[str, dict]] = []
            if self.yara:
                self.yara.reload_if_updated()
                matches = self.yara.scan_file(fp)
                meta = self.yara.scan_file_meta(fp)
            self._cache[path] = (digest, mtime, matches, meta)
        logger.debug(f"Scanned {path} hash={digest} matches={matches}")
        return {"hash": digest, "yara": matches, "yara_meta": meta}

    def scan_bytes(self, data: bytes) -> List[str]:
        """Scan in-memory *data* with YARA and return rule names."""
        if self.yara:
            self.yara.reload_if_updated()
            return self.yara.scan_bytes(data)
        return []

    def scan_bytes_meta(self, data: bytes) -> List[tuple[str, dict]]:
        """Scan bytes and return (rule, meta) tuples."""
        if self.yara:
            self.yara.reload_if_updated()
            return self.yara.scan_bytes_meta(data)
        return []
