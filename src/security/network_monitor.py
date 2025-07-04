from __future__ import annotations

import threading
import time
import sys
from typing import Callable, List, TYPE_CHECKING

from utils.psutil_compat import psutil

try:
    from psutil._common import sconn as SConn  # type: ignore
except Exception:  # pragma: no cover - fallback when psutil is missing
    from dataclasses import dataclass

    @dataclass
    class Addr:
        ip: str
        port: int

    @dataclass
    class SConn:  # minimal replacement for psutil's sconn
        raddr: Addr | None = None
        laddr: Addr | None = None
        pid: int | None = None
        fd: int | None = None
        family: int | None = None
        type: int | None = None
        status: str | None = None
from .privileges import require_privileges

if TYPE_CHECKING:  # pragma: no cover - for type hints
    from .privileges import PrivilegeManager

try:  # optional
    from core.analyzer import PatternAnalyzer
except Exception:  # pragma: no cover - during build
    PatternAnalyzer = None


class NetworkMonitor:
    """Monitor system network connections for suspicious activity."""

    def __init__(
        self,
        patterns: dict,
        interval: float = 5.0,
        priv_manager: "PrivilegeManager | None" = None,
        analyzer: "PatternAnalyzer | None" = None,
        cache_ttl: float = 60.0,
    ) -> None:
        self.patterns = patterns
        self.interval = interval
        self.cache_ttl = cache_ttl
        self._thread: threading.Thread | None = None
        self._running = False
        self._seen: dict[tuple[int, str, int], float] = {}
        self.on_suspicious: Callable[[SConn], None] | None = None
        if priv_manager is None:
            from security.privileges import PrivilegeManager

            priv_manager = PrivilegeManager()
        self.priv_manager = priv_manager
        self.analyzer = analyzer

    # start/stop monitoring
    @require_privileges(["SeDebugPrivilege"], impersonate=False)
    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join()

    def _loop(self) -> None:
        while self._running:
            for conn in self._check_once():
                if self.on_suspicious:
                    self.on_suspicious(conn)
            time.sleep(self.interval)

    # public method for one-off scan

    def check_now(self) -> List[SConn]:
        return self._check_once()

    def _check_once(self) -> List[SConn]:
        suspicious: List[SConn] = []
        now = time.time()
        if sys.platform == "win32":
            self.priv_manager.ensure_active(["SeDebugPrivilege"], impersonate=False)
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception:
            return suspicious
        for c in conns:
            if not c.raddr:
                continue
            key = (c.pid or -1, str(c.raddr.ip), int(c.raddr.port))
            ts = self._seen.get(key)
            if ts and now - ts < self.cache_ttl:
                continue
            matched = False
            if self.analyzer is not None:
                res = self.analyzer.analyze_connection(str(c.raddr.ip), c.raddr.port)
                if res.level in ["medium", "high", "critical"]:
                    matched = True
            else:
                ports = set(self.patterns.get("suspicious_ports", []))
                ip_prefixes = self.patterns.get("suspicious_ips", [])
                if c.raddr.port in ports or any(str(c.raddr.ip).startswith(p) for p in ip_prefixes):
                    matched = True
            if matched:
                suspicious.append(c)
                self._seen[key] = now
        # purge expired entries
        expired = [k for k, t in self._seen.items() if now - t > self.cache_ttl]
        for k in expired:
            self._seen.pop(k, None)
        return suspicious
