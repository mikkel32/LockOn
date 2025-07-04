from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

from .helpers import parse_threat_details, highlight


@dataclass
class ThreatSummary:
    """Summarized information about a detected threat."""

    path: str | Path
    level: str
    type: str | None
    match: str | None
    snippet: str | None
    line: int | None
    details: Dict[str, Any]

    @classmethod
    def from_detection(cls, path: str | Path, risk: Any) -> "ThreatSummary":
        """Create a :class:`ThreatSummary` from a risk object."""
        details = risk.details if isinstance(getattr(risk, "details", None), dict) else {}
        snippet, match, line = parse_threat_details(details)
        return cls(
            path=path,
            level=getattr(risk, "level", "unknown"),
            type=getattr(risk, "type", None),
            match=match,
            snippet=snippet,
            line=line,
            details=details,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "path": str(self.path),
            "level": self.level,
            "type": self.type,
            "match": self.match,
            "snippet": self.snippet,
            "line": self.line,
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ThreatSummary":
        return cls(
            path=data.get("path"),
            level=data.get("level", "unknown"),
            type=data.get("type"),
            match=data.get("match"),
            snippet=data.get("snippet"),
            line=data.get("line"),
            details=data.get("details") or {},
        )

    @classmethod
    def from_db_row(
        cls, path: str | Path, level: str, ttype: str | None, details_json: str | None
    ) -> "ThreatSummary":
        """Build summary from database row values."""
        import json

        details: Dict[str, Any] = {}
        if details_json:
            try:
                details = json.loads(details_json)
            except Exception:
                details = {}
        snippet, match, line = parse_threat_details(details)
        return cls(path, level, ttype, match, snippet, line, details)

    def format(self, color: bool = False) -> str:
        """Return formatted log string."""
        parts = [f"Threat detected: {self.path}", f"- Level: {self.level}"]
        if self.type:
            parts.append(f"Type: {self.type}")
        if self.match:
            parts.append(f"Match: {self.match}")
        if self.snippet:
            loc = f"(line {self.line}) " if self.line else ""
            parts.append(f"Snippet: {loc}{self.snippet}")
        msg = " ".join(parts)

        if not color:
            return msg

        def clr(text: str, code: str) -> str:
            return f"\033[{code}m{text}\033[0m"

        level_code = {"critical": "31", "high": "31", "medium": "33", "low": "32"}.get(
            self.level.lower(), "36"
        )
        colored = [
            f"Threat detected: {clr(str(self.path), '36')}",
            f"- Level: {clr(self.level, level_code)}",
        ]
        if self.type:
            colored.append(f"Type: {clr(self.type, '35')}")
        if self.match:
            colored.append(f"Match: {clr(self.match, '35')}")
        if self.snippet:
            loc = f"(line {self.line}) " if self.line else ""
            snippet = self.snippet
            if self.match:
                snippet = highlight(snippet, self.match, "31")
            colored.append(f"Snippet: {loc}{clr(snippet, '34')}")
        return " ".join(colored)

    def __str__(self) -> str:  # pragma: no cover - simple proxy
        return self.format(False)

