"""Minimal YARA scanner wrapper with pure Python fallback."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import List, Dict, Iterable, Tuple

try:  # pragma: no cover - optional dependency
    import yara  # type: ignore
except Exception:
    yara = None

logger = logging.getLogger("LockOn")


class YaraScanner:
    """Wrapper around YARA with a simplified regex fallback."""

    def __init__(self, rules_path: Path | str | None = None) -> None:
        self.rules = None
        self.threat_map: Dict[str, str] = {}
        self._fallback_rules: List[Tuple[str, Dict[str, str], str, Dict[str, re.Pattern]]] = []
        if rules_path:
            self.rules_path = Path(rules_path)
        else:
            from utils.paths import resource_path
            self.rules_path = resource_path("Intelligence", "yara_rules.yar")
        self._mtime = 0.0
        self._load_rules()

    def _load_rules(self) -> None:
        """Compile rules and build the threat map."""
        if not self.rules_path.exists():
            logger.warning("YARA rules file %s not found", self.rules_path)
            return

        if yara is None:
            logger.debug("yara-python not available, using simplified regex rules")
            self._load_fallback()
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

    def _load_fallback(self) -> None:
        """Parse rules file and build simple regex-based rules."""
        self._fallback_rules.clear()
        self.threat_map = {}
        self._mtime = self.rules_path.stat().st_mtime
        current: Tuple[str, Dict[str, str], str, Dict[str, re.Pattern]] | None = None
        section = None
        for raw in self.rules_path.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("//"):
                continue
            if line.startswith("rule "):
                if current:
                    self._fallback_rules.append(current)
                    threat = current[1].get("threat")
                    if threat:
                        self.threat_map[current[0].lower()] = threat.lower()
                # handle one-line rule definitions
                if "{" in line and "}" in line:
                    body = line[line.index("{")+1:line.rindex("}")]
                    name = line.split()[1]
                    current = (name, {}, "", {})
                    section = None
                    for part in body.split(';'):
                        seg = part.strip()
                        if not seg:
                            continue
                        if seg.startswith("condition:"):
                            current = (current[0], current[1], seg.split(":",1)[1].strip(), current[3])
                    self._fallback_rules.append(current)
                    threat = current[1].get("threat")
                    if threat:
                        self.threat_map[current[0].lower()] = threat.lower()
                    current = None
                    section = None
                    continue
                name = line.split()[1]
                current = (name, {}, "", {})
                section = None
            elif line.startswith("meta:"):
                section = "meta"
            elif line.startswith("strings:"):
                section = "strings"
            elif line.startswith("condition:"):
                section = "condition"
            elif line.startswith("}"):
                if current:
                    self._fallback_rules.append(current)
                    threat = current[1].get("threat")
                    if threat:
                        self.threat_map[current[0].lower()] = threat.lower()
                    current = None
                    section = None
            elif current and section == "meta":
                if "=" in line:
                    k, v = line.split("=", 1)
                    current[1][k.strip()] = v.strip().strip('"')
            elif current and section == "strings":
                m = re.match(r"\$(\w+)\s*=\s*(.+)", line)
                if m:
                    var, val = m.groups()
                    if val.endswith("nocase"):
                        val = val[:-6].strip()
                        flags = re.IGNORECASE
                    else:
                        flags = 0
                    if val.startswith("/") and val.rfind("/") > 0:
                        body, flagpart = val[1:].rsplit("/", 1)
                        if "i" in flagpart:
                            flags |= re.IGNORECASE
                        pattern = re.compile(body.encode(), flags)
                    elif val.startswith("{") and val.endswith("}"):
                        hex_bytes = bytes.fromhex(val[1:-1].replace(" ", ""))
                        pattern = re.compile(re.escape(hex_bytes))
                    else:
                        literal = val.strip('"')
                        literal = bytes(literal, 'utf-8').decode('unicode_escape')
                        pattern = re.compile(re.escape(literal).encode(), flags)
                    current[3][var] = pattern
            elif current and section == "condition":
                current = (current[0], current[1], current[2] + " " + line if current[2] else line, current[3])
        if current:
            self._fallback_rules.append(current)
            threat = current[1].get("threat")
            if threat:
                self.threat_map[current[0].lower()] = threat.lower()

    def reload_if_updated(self) -> None:
        """Reload YARA rules if the file changed."""
        if not self.rules_path.exists():
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
        if self.rules:
            try:
                matches = self.rules.match(str(filepath))
                return [m.rule for m in matches]
            except Exception as exc:  # pragma: no cover - scan error
                logger.warning("YARA scan error on %s: %s", filepath, exc)
                return []
        return [name for name, _ in self._scan_bytes_fallback(Path(filepath).read_bytes())]

    def scan_file_meta(self, filepath: Path) -> List[tuple[str, dict]]:
        """Return list of (rule name, meta) tuples for *filepath*."""
        self.reload_if_updated()
        if self.rules:
            try:
                matches = self.rules.match(str(filepath))
                return [(m.rule, m.meta) for m in matches]
            except Exception as exc:
                logger.warning("YARA scan error on %s: %s", filepath, exc)
                return []
        matches = self._scan_bytes_fallback(Path(filepath).read_bytes())
        return matches

    def scan_bytes(self, data: bytes) -> List[str]:
        """Return list of matching rule names for in-memory *data*."""
        self.reload_if_updated()
        if self.rules:
            try:
                matches = self.rules.match(data=data)
                return [m.rule for m in matches]
            except Exception as exc:  # pragma: no cover - scan error
                logger.warning("YARA scan error on bytes: %s", exc)
                return []
        return [name for name, _ in self._scan_bytes_fallback(data)]

    def scan_bytes_meta(self, data: bytes) -> List[tuple[str, dict]]:
        """Return list of (rule name, meta) tuples for in-memory *data*."""
        self.reload_if_updated()
        if self.rules:
            try:
                matches = self.rules.match(data=data)
                return [(m.rule, m.meta) for m in matches]
            except Exception as exc:
                logger.warning("YARA scan error on bytes: %s", exc)
                return []
        return self._scan_bytes_fallback(data)

    # ------------------------------------------------------------------
    # Fallback engine
    # ------------------------------------------------------------------

    def _evaluate_condition(self, expr: str, matches: Iterable[str], start: Iterable[str], total: int) -> bool:
        """Evaluate simplified condition expression."""
        cond = expr
        cond = cond.replace("any of them", "len(matches) > 0")
        cond = cond.replace("all of them", f"len(matches) == {total}")
        cond = cond.replace("true", "True").replace("false", "False")
        cond = re.sub(r"\$(\w+)\s+at\s+0", lambda m: f"'{m.group(1)}' in start", cond)
        cond = re.sub(r"\$(\w+)", lambda m: f"'{m.group(1)}' in matches", cond)
        try:
            return bool(eval(cond, {"matches": set(matches), "start": set(start), "len": len}))
        except Exception:
            return bool(matches)

    def _scan_bytes_fallback(self, data: bytes) -> List[Tuple[str, Dict[str, str]]]:
        results: List[Tuple[str, Dict[str, str]]] = []
        for name, meta, cond, patterns in self._fallback_rules:
            matched = set()
            start = set()
            for pname, regex in patterns.items():
                m = regex.search(data)
                if m:
                    matched.add(pname)
                    if m.start() == 0:
                        start.add(pname)
            if self._evaluate_condition(cond, matched, start, len(patterns)):
                results.append((name, meta))
        return results
