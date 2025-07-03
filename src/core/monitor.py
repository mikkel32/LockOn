"""
Folder Monitor - Real-time file system monitoring with threat detection
"""

import os
import time
import threading
import sys
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
from collections import deque
import queue

from utils.database import Database

try:  # optional watchdog dependency
    from watchdog.observers import Observer  # type: ignore
    from watchdog.events import FileSystemEventHandler, FileSystemEvent  # type: ignore

    WATCHDOG_AVAILABLE = True
except Exception:  # pragma: no cover - provide fallback
    WATCHDOG_AVAILABLE = False

    class FileSystemEvent:
        """Minimal stand-in for ``watchdog`` events."""

        def __init__(
            self,
            src_path: str,
            is_directory: bool = False,
            dest_path: str | None = None,
        ) -> None:
            self.src_path = src_path
            self.dest_path = dest_path
            self.is_directory = is_directory

    class FileSystemEventHandler:
        """Base event handler used when ``watchdog`` is unavailable."""

        class _PollingObserver:
            """Very small polling based observer as a fallback."""

            def __init__(self, interval: float = 1.0) -> None:
                self.interval = interval
                self._handlers: list[
                    tuple[FileSystemEventHandler, Path, bool, dict[str, float]]
                ] = []
                self._thread: threading.Thread | None = None
                self._running = False

            def schedule(
                self, handler: FileSystemEventHandler, path: str, recursive: bool = True
            ) -> None:
                self._handlers.append((handler, Path(path), recursive, {}))

            def start(self) -> None:
                if self._running:
                    return
                self._running = True
                self._thread = threading.Thread(target=self._loop, daemon=True)
                self._thread.start()

            def _loop(self) -> None:
                while self._running:
                    for handler, path, recursive, snapshot in self._handlers:
                        self._scan(handler, path, recursive, snapshot)
                    time.sleep(self.interval)

            def _scan(
                self,
                handler: FileSystemEventHandler,
                path: Path,
                recursive: bool,
                snapshot: dict[str, float],
            ) -> None:
                current: dict[str, float] = {}
                walker = os.walk(path) if recursive else [(path, [], os.listdir(path))]
                for root, _, files in walker:
                    for name in files:
                        fp = Path(root) / name
                        try:
                            mtime = fp.stat().st_mtime
                        except FileNotFoundError:
                            continue
                        current[str(fp)] = mtime
                        if str(fp) not in snapshot:
                            event = FileSystemEvent(str(fp))
                            if hasattr(handler, "on_created"):
                                handler.on_created(event)
                        elif snapshot[str(fp)] != mtime:
                            event = FileSystemEvent(str(fp))
                            if hasattr(handler, "on_modified"):
                                handler.on_modified(event)

                # handle deletions
                for old in list(snapshot):
                    if old not in current:
                        event = FileSystemEvent(old)
                        if hasattr(handler, "on_deleted"):
                            handler.on_deleted(event)
                        snapshot.pop(old, None)

                snapshot.update(current)

            def stop(self) -> None:
                self._running = False
                if self._thread:
                    self._thread.join()

            def join(self, timeout: float | None = None) -> None:
                if self._thread:
                    self._thread.join(timeout)

        Observer = _PollingObserver


from utils.psutil_compat import psutil


@dataclass
class FileEvent:
    """Filesystem event used for async dispatch."""

    action: str
    path: Path | tuple[Path, Path]
    timestamp: datetime


from core.analyzer import PatternAnalyzer
from core.enforcer import ActionEnforcer
from utils.logger import SecurityLogger
from security.network_monitor import NetworkMonitor


class FolderMonitor(FileSystemEventHandler):
    """Advanced folder monitoring system"""

    def __init__(
        self,
        priv_manager: "PrivilegeManager | None" = None,
        watch_interval: float = 30.0,
        watchlist: Optional[List[Path]] = None,
        db: "Database | None" = None,
    ):
        """Initialize the monitor.

        Parameters
        ----------
        priv_manager:
            Optional :class:`~security.privileges.PrivilegeManager` instance.
        watch_interval:
            Seconds between watchlist scans.
        watchlist:
            Initial watchlist paths.
        db:
            Optional database used to persist watchlist changes.
        """
        super().__init__()
        self.logger = SecurityLogger()
        self.analyzer = PatternAnalyzer()
        from security.privileges import PrivilegeManager

        self.priv_manager = priv_manager or PrivilegeManager(auto_monitor=True)
        self.enforcer = ActionEnforcer(priv_manager=self.priv_manager)
        self.net_monitor = NetworkMonitor(
            self.analyzer.intelligence.patterns,
            priv_manager=self.priv_manager,
            analyzer=self.analyzer,
        )
        self.net_monitor.on_suspicious = self._handle_network_threat

        self.target_folder: Optional[Path] = None
        self.observer: Optional[Observer] = None
        self.shield_active = False
        self.monitoring = False
        self.watch_interval = watch_interval
        self._default_interval = watch_interval
        self._last_threat_count = 0

        # Statistics
        self.stats = {
            "files_monitored": 0,
            "threats_detected": 0,
            "actions_taken": 0,
            "start_time": None,
        }

        # File tracking
        self.file_hashes: Dict[str, str] = {}
        self.file_mtimes: Dict[str, float] = {}
        self.file_activity: Dict[str, List[datetime]] = {}
        self.suspicious_processes: List[int] = []

        # event queue and history
        self._event_queue: "queue.Queue[FileEvent]" = queue.Queue()
        self.recent_events: deque[FileEvent] = deque(maxlen=1000)
        self._dispatcher: threading.Thread | None = None
        self.watchlist: dict[Path, float] = {}
        for p in watchlist or []:
            p = Path(p)
            try:
                self.watchlist[p] = p.stat().st_mtime
            except Exception:
                self.watchlist[p] = 0.0
        self.db = db
        if self.db:
            try:
                for entry in self.db.get_watchlist():
                    p = Path(entry)
                    if p not in self.watchlist:
                        try:
                            self.watchlist[p] = p.stat().st_mtime
                        except Exception:
                            self.watchlist[p] = 0.0
                for p, (h, mtime) in self.db.load_hashes().items():
                    self.file_hashes[p] = h
                    self.file_mtimes[p] = mtime
            except Exception:
                pass
        self._watcher_thread: threading.Thread | None = None
        self.process_monitor_thread: threading.Thread | None = None
        self.scan_thread: threading.Thread | None = None

        self.on_network_threat: Optional[Callable] = None

        # Callbacks
        self.on_threat_detected: Optional[Callable] = None
        self.on_file_changed: Optional[Callable] = None
        self.on_ready: Optional[Callable[[List[Path]], None]] = None

    # ------------------------------------------------------------------
    # context manager helpers
    # ------------------------------------------------------------------
    def __enter__(self) -> "FolderMonitor":
        """Allow use in ``with`` statements."""
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        """Ensure monitoring stops on exit."""
        self.stop()

    def set_target_folder(self, folder: str):
        """Set the folder to monitor"""
        self.target_folder = Path(folder)
        self.logger.info(f"Target folder set to: {folder}")

        # Initial scan
        self._scan_folder()

    def scan_now(self) -> None:
        """Manually rescan the target folder."""
        self._scan_folder()

    def _scan_folder(self):
        """Initial scan of target folder"""
        if not self.target_folder or not self.target_folder.exists():
            return

        self.logger.info("Starting initial folder scan...")

        files: list[Path] = []
        for root, dirs, file_names in os.walk(self.target_folder):
            for name in file_names:
                files.append(Path(root) / name)

        def _worker(fp: Path) -> None:
            try:
                mtime = fp.stat().st_mtime
            except FileNotFoundError:
                return

            stored_mtime = self.file_mtimes.get(str(fp))
            if stored_mtime == mtime and str(fp) in self.file_hashes:
                # file unchanged, reuse stored hash and skip analysis
                return

            try:
                file_hash = self._calculate_hash(fp)
                self.file_hashes[str(fp)] = file_hash
                self.file_mtimes[str(fp)] = mtime
                if self.db:
                    try:
                        self.db.update_hash(str(fp), file_hash, mtime)
                    except Exception:
                        pass
                risk = self.analyzer.analyze_file(fp)
                if risk.level in ["high", "critical"]:
                    self.logger.warning(f"High-risk file found: {fp}")
                    self._handle_threat(fp, risk)
            except Exception as exc:
                self.logger.error(f"Error scanning {fp}: {exc}")

        from concurrent.futures import ThreadPoolExecutor

        workers = min(4, os.cpu_count() or 1)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            pool.map(_worker, files)

        self.stats["files_monitored"] = len(self.file_hashes)
        self.logger.info(
            f"Initial scan complete. {self.stats['files_monitored']} files indexed."
        )
        if self.on_ready:
            try:
                self.on_ready(self.get_tracked_files())
            except Exception:
                pass

    def _calculate_hash(self, filepath: Path) -> str:
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as exc:
            self.logger.error(f"Hashing failed for {filepath}: {exc}")
            return ""

    def start(self):
        """Start monitoring"""
        if not self.target_folder:
            self.logger.error("No target folder set")
            return

        try:
            from security.privileges import has_privilege, ALL_PRIVILEGES

            missing = self.priv_manager.ensure(ALL_PRIVILEGES)
            critical = [
                "SeBackupPrivilege",
                "SeRestorePrivilege",
                "SeDebugPrivilege",
                "SeSecurityPrivilege",
            ]
            missing += [p for p in critical if not has_privilege(p)]
            if missing:
                self.logger.warning(
                    f"Missing privileges: {', '.join(sorted(set(missing)))}"
                )
            else:
                self.logger.debug("All critical privileges enabled")
        except Exception as exc:
            self.logger.error(f"Privilege elevation failed: {exc}")

        # Refresh baseline before starting threads
        self.scan_now()

        self.monitoring = True
        self.stats["start_time"] = datetime.now()
        # start dispatcher thread
        self._dispatcher = threading.Thread(target=self._dispatch_loop, daemon=True)
        self._dispatcher.start()
        # start watchlist thread
        self._watcher_thread = threading.Thread(target=self._watchlist_scan, daemon=True)
        self._watcher_thread.start()

        # Start file system observer
        self.observer = Observer()
        self.observer.schedule(self, str(self.target_folder), recursive=True)
        self.observer.start()

        # Start process monitor
        self.process_monitor_thread = threading.Thread(target=self._monitor_processes)
        self.process_monitor_thread.daemon = True
        self.process_monitor_thread.start()

        # Start network monitor
        self.net_monitor.start()

        # Start periodic security scan
        self.scan_thread = threading.Thread(target=self._periodic_scan)
        self.scan_thread.daemon = True
        self.scan_thread.start()

        self.logger.info("Monitoring started")

    def stop(self):
        """Stop monitoring"""
        self.monitoring = False

        if self.observer:
            self.observer.stop()
            self.observer.join()

        self.net_monitor.stop()

        if self.process_monitor_thread:
            self.process_monitor_thread.join()
            self.process_monitor_thread = None

        if self.scan_thread:
            self.scan_thread.join()
            self.scan_thread = None

        if self._dispatcher:
            self._dispatcher.join()
            self._dispatcher = None

        if self._watcher_thread:
            self._watcher_thread.join()
            self._watcher_thread = None

        while not self._event_queue.empty():
            try:
                self._event_queue.get_nowait()
            except queue.Empty:
                break

        self.logger.info("Monitoring stopped")

    def on_created(self, event: FileSystemEvent):
        """Handle file creation"""
        if event.is_directory:
            return

        filepath = Path(event.src_path)
        self.logger.debug(f"File created: {filepath}")

        # Analyze new file
        risk = self.analyzer.analyze_file(filepath)

        if risk.level in ["high", "critical"]:
            self.logger.warning(f"Suspicious file created: {filepath}")
            self._handle_threat(filepath, risk)
        else:
            # Calculate hash for tracking
            digest = self._calculate_hash(filepath)
            self.file_hashes[str(filepath)] = digest
            try:
                mtime = filepath.stat().st_mtime
            except Exception:
                mtime = 0.0
            self.file_mtimes[str(filepath)] = mtime
            if self.db:
                try:
                    self.db.update_hash(str(filepath), digest, mtime)
                except Exception:
                    pass

        self._track_activity(filepath, "created")
        self._queue_event("created", filepath)
        if self.db:
            try:
                self.db.log_event(str(filepath), "created")
            except Exception:
                pass

    def on_modified(self, event: FileSystemEvent):
        """Handle file modification"""
        if event.is_directory:
            return

        filepath = Path(event.src_path)
        self.logger.debug(f"File modified: {filepath}")

        # Check for hash change
        old_hash = self.file_hashes.get(str(filepath), "")
        new_hash = self._calculate_hash(filepath)
        
        if old_hash and old_hash != new_hash:
            # File content changed
            self.logger.info(f"File content changed: {filepath}")

            # Check for encryption patterns
            if self.analyzer.detect_encryption(filepath, old_hash, new_hash):
                self.logger.critical(f"Possible encryption detected: {filepath}")
                self._handle_critical_threat(filepath, "encryption")

        self.file_hashes[str(filepath)] = new_hash
        try:
            mtime = filepath.stat().st_mtime
        except Exception:
            mtime = 0.0
        self.file_mtimes[str(filepath)] = mtime
        if self.db:
            try:
                self.db.update_hash(str(filepath), new_hash, mtime)
            except Exception:
                pass
        self._track_activity(filepath, "modified")
        self._queue_event("modified", filepath)
        if self.db:
            try:
                self.db.log_event(str(filepath), "modified")
            except Exception:
                pass

    def on_deleted(self, event: FileSystemEvent):
        """Handle file deletion"""
        if event.is_directory:
            return

        filepath = Path(event.src_path)
        self.logger.info(f"File deleted: {filepath}")

        # Check if this is suspicious deletion
        if self._is_suspicious_deletion(filepath):
            self.logger.warning(f"Suspicious deletion: {filepath}")
            if self.shield_active:
                # Attempt to restore
                self.enforcer.restore_file(filepath)

        # Remove from tracking
        self.file_hashes.pop(str(filepath), None)
        self.file_mtimes.pop(str(filepath), None)
        if self.db:
            try:
                self.db.delete_hash(str(filepath))
            except Exception:
                pass
        self._track_activity(filepath, "deleted")
        self._queue_event("deleted", filepath)
        if self.db:
            try:
                self.db.log_event(str(filepath), "deleted")
            except Exception:
                pass

    def on_moved(self, event: FileSystemEvent):
        """Handle file move/rename"""
        if event.is_directory:
            return

        src_path = Path(event.src_path)
        dest_path = Path(event.dest_path)

        self.logger.info(f"File moved: {src_path} -> {dest_path}")

        # Update tracking
        if str(src_path) in self.file_hashes:
            digest = self.file_hashes.pop(str(src_path))
            self.file_hashes[str(dest_path)] = digest
            mtime = self.file_mtimes.pop(str(src_path), 0.0)
            try:
                mtime = dest_path.stat().st_mtime
            except Exception:
                pass
            self.file_mtimes[str(dest_path)] = mtime
            if self.db:
                try:
                    self.db.delete_hash(str(src_path))
                    self.db.update_hash(str(dest_path), digest, mtime)
                except Exception:
                    pass

        self._track_activity(dest_path, "moved")
        self._queue_event("moved", (src_path, dest_path))
        if self.db:
            try:
                self.db.log_event(f"{src_path}->{dest_path}", "moved")
            except Exception:
                pass

    def _track_activity(self, filepath: Path, action: str):
        """Track file activity for behavior analysis"""
        key = str(filepath)
        if key not in self.file_activity:
            self.file_activity[key] = []

        self.file_activity[key].append(datetime.now())

        # Check for rapid activity
        recent_activity = [
            t for t in self.file_activity[key] if (datetime.now() - t).seconds < 60
        ]

        if len(recent_activity) > 10:
            self.logger.warning(
                f"Rapid activity on {filepath}: {len(recent_activity)} actions/min"
            )
            self._check_behavior_patterns()
        self._analyze_file_activity(filepath)

    def _is_suspicious_deletion(self, filepath: Path) -> bool:
        """Check if deletion is suspicious"""
        # Check if system/important file
        suspicious_patterns = ["system", "config", "important", "critical"]
        if any(pattern in str(filepath).lower() for pattern in suspicious_patterns):
            return True

        # Check deletion rate
        recent_deletions = sum(
            1
            for _, activities in self.file_activity.items()
            if any((datetime.now() - t).seconds < 60 for t in activities)
        )

        return recent_deletions > 20

    def _handle_threat(self, filepath: Path, risk):
        """Handle detected threat"""
        self.stats["threats_detected"] += 1

        self.logger.warning(f"Threat detected: {filepath} - Risk: {risk.level}")
        if self.db:
            try:
                self.db.log_threat(str(filepath), risk.level, risk.type)
            except Exception:
                pass

        # Take action based on risk level
        if risk.level == "critical":
            self._handle_critical_threat(filepath, risk.type)
        elif risk.level == "high":
            self._handle_high_threat(filepath, risk.type)
        else:
            self._handle_medium_threat(filepath, risk.type)

        # Notify callback
        if self.on_threat_detected:
            self.on_threat_detected(filepath, risk)

        self.stats["actions_taken"] += 1

    def _handle_critical_threat(self, filepath: Path, threat_type: str):
        """Handle critical threats"""
        self.logger.critical(f"CRITICAL THREAT: {filepath} - Type: {threat_type}")

        # Immediate actions
        if threat_type == "ransomware":
            # Emergency lockdown
            self.enforcer.emergency_lockdown(self.target_folder)
            # Kill suspicious processes
            self._terminate_suspicious_processes()
            # Backup critical files
            self.enforcer.emergency_backup(self.target_folder)

        elif threat_type == "encryption":
            # Quarantine file
            self.enforcer.quarantine_file(filepath)
            # Block process
            self._block_file_process(filepath)

        else:
            # Generic critical response
            self.enforcer.quarantine_file(filepath)
            self.enforcer.block_file_access(filepath)

    def _handle_high_threat(self, filepath: Path, threat_type: str):
        """Handle high-level threats"""
        self.logger.warning(f"HIGH THREAT: {filepath} - Type: {threat_type}")

        # Quarantine and monitor
        self.enforcer.quarantine_file(filepath)

        # Increase monitoring on related files
        self._increase_monitoring(filepath.parent)

    def _handle_medium_threat(self, filepath: Path, threat_type: str):
        """Handle medium-level threats"""
        self.logger.info(f"MEDIUM THREAT: {filepath} - Type: {threat_type}")

        # Monitor closely
        self._add_to_watchlist(filepath)

        # Restrict permissions
        self.enforcer.restrict_permissions(filepath)

    def _monitor_processes(self):
        """Monitor system processes for suspicious activity"""
        while self.monitoring:
            self.check_processes_now()
            time.sleep(5)  # Check every 5 seconds

    def check_processes_now(self) -> None:
        """Scan running processes a single time."""
        if sys.platform == "win32":
            try:
                self.priv_manager.ensure_active(["SeDebugPrivilege"], impersonate=False)
            except Exception:
                pass
        try:
            for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info"]):
                try:
                    cpu = proc.cpu_percent(interval=None)
                    mem = getattr(proc, "memory_info", lambda: None)()
                    suspicious = self.analyzer.is_suspicious_process(proc)
                    heavy = cpu > 80 or (mem and getattr(mem, "rss", 0) > 200 * 1024 * 1024)
                    if suspicious or heavy:
                        if proc.pid not in self.suspicious_processes:
                            self.suspicious_processes.append(proc.pid)
                            self.logger.warning(
                                f"Suspicious process detected: {proc.info['name']} (PID: {proc.pid}) cpu={cpu}%"
                            )
                            if self.db:
                                try:
                                    entry = f"{proc.pid}:{proc.info['name']}"
                                    level = "high" if suspicious else "medium"
                                    self.db.log_threat(entry, level, "process")
                                except Exception:
                                    pass
                            self.stats["threats_detected"] += 1
                            if self.shield_active:
                                self.enforcer.handle_suspicious_process(proc)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            self.logger.error(f"Process monitoring error: {e}")

    def _periodic_scan(self):
        """Periodic security scan"""
        while self.monitoring:
            for _ in range(300):
                if not self.monitoring:
                    return
                time.sleep(1)

            try:
                if sys.platform == "win32":
                    try:
                        self.priv_manager.ensure_active(
                            ["SeDebugPrivilege"], impersonate=False
                        )
                    except Exception:
                        pass
                self.logger.debug("Running periodic security scan...")

                # Check for new threats
                for filepath_str, file_hash in list(self.file_hashes.items()):
                    filepath = Path(filepath_str)
                    if filepath.exists():
                        # Re-analyze files
                        risk = self.analyzer.analyze_file(filepath)
                        if risk.level in ["high", "critical"]:
                            self._handle_threat(filepath, risk)

                # Check behavior patterns
                self._check_behavior_patterns()

                # Update stats
                self.stats["files_monitored"] = len(self.file_hashes)

            except Exception as e:
                self.logger.error(f"Periodic scan error: {e}")

    def _check_behavior_patterns(self):
        """Analyze behavior patterns for anomalies"""
        # Check for mass file changes
        recent_changes = sum(
            len([t for t in activities if (datetime.now() - t).seconds < 300])
            for activities in self.file_activity.values()
        )

        if recent_changes > 500:
            self.logger.critical("Mass file changes detected - possible ransomware!")
            self._handle_critical_threat(self.target_folder, "mass_changes")

    def _analyze_file_activity(self, filepath: Path) -> None:
        """Heuristic analysis on per-file activity."""
        activities = self.file_activity.get(str(filepath), [])
        recent = [t for t in activities if (datetime.now() - t).seconds < 30]
        if len(recent) >= 5:
            self.logger.warning(f"Repeated changes to {filepath}: {len(recent)} in 30s")
            self._check_behavior_patterns()

    def _terminate_suspicious_processes(self):
        """Terminate all suspicious processes"""
        for pid in self.suspicious_processes:
            try:
                proc = psutil.Process(pid)
                self.logger.warning(
                    f"Terminating suspicious process: {proc.name()} (PID: {pid})"
                )
                proc.terminate()
                proc.wait(timeout=5)
                if proc.is_running():
                    proc.kill()
            except Exception as exc:
                self.logger.error(f"Failed to terminate process {pid}: {exc}")

        self.suspicious_processes.clear()

    def _block_file_process(self, filepath: Path):
        """Block process that accessed the file"""
        # Get process that has file open
        for proc in psutil.process_iter(["pid", "name", "open_files"]):
            try:
                if proc.info["open_files"]:
                    for f in proc.info["open_files"]:
                        if str(filepath) in f.path:
                            self.logger.warning(
                                f"Blocking process {proc.info['name']} accessing {filepath}"
                            )
                            self.enforcer.handle_suspicious_process(proc)
                            break
            except Exception as exc:
                self.logger.error(f"Process blocking failed: {exc}")

    def _increase_monitoring(self, directory: Path):
        """Increase monitoring frequency for *directory* by adding it to the watchlist."""
        self.add_watch_path(directory)
        self.logger.info(f"Increased monitoring on: {directory}")

    def _add_to_watchlist(self, filepath: Path):
        """Add *filepath* to the watchlist for aggressive scanning."""
        self.add_watch_path(filepath)

    def _handle_network_threat(self, conn) -> None:
        """Handle suspicious network connection detected by NetworkMonitor."""
        try:
            ip = conn.raddr.ip
            port = conn.raddr.port
            pid = conn.pid
        except Exception:
            return
        analysis = self.analyzer.analyze_connection(ip, port)
        self.logger.warning(
            f"Suspicious connection {ip}:{port} (PID {pid}) risk={analysis.level}"
        )
        if self.db:
            try:
                entry = f"{pid}:{ip}:{port}"
                self.db.log_threat(entry, analysis.level, "network")
            except Exception:
                pass
        self.stats["threats_detected"] += 1
        if self.on_network_threat:
            self.on_network_threat(conn)
        if self.shield_active and pid:
            try:
                proc = psutil.Process(pid)
                if self.analyzer.is_suspicious_process(proc) or analysis.level in [
                    "high",
                    "critical",
                ]:
                    self.enforcer.handle_suspicious_process(proc)
            except Exception:
                pass

    def activate_shield(self):
        """Activate protective shield"""
        self.shield_active = True
        self.logger.info("Protective shield ACTIVATED")

        # Increase security measures
        self.enforcer.enable_active_protection()

    def deactivate_shield(self):
        """Deactivate protective shield"""
        self.shield_active = False
        self.logger.info("Protective shield DEACTIVATED")

        self.enforcer.disable_active_protection()

    def emergency_stop(self):
        """Emergency stop all monitoring"""
        self.logger.critical("EMERGENCY STOP ACTIVATED")
        self.monitoring = False
        self.shield_active = False

        # Stop all threads
        if self.observer:
            self.observer.stop()

        self.net_monitor.stop()

        # Terminate suspicious processes
        self._terminate_suspicious_processes()

    def get_tracked_files(self) -> List[Path]:
        """Return a list of currently tracked file paths."""
        return [Path(p) for p in sorted(self.file_hashes.keys())]

    def build_file_tree(self) -> str:
        """Return an ASCII tree of all tracked files."""
        if not self.target_folder:
            return ""
        return self._build_tree(self.get_tracked_files(), self.target_folder)

    @staticmethod
    def _build_tree(paths: List[Path], base: Path) -> str:
        from collections import defaultdict

        def tree() -> defaultdict:
            return defaultdict(tree)

        root = tree()
        for p in paths:
            rel = p.relative_to(base)
            node = root
            for part in rel.parts[:-1]:
                node = node[part]
            node[rel.parts[-1]] = None

        def walk(node, prefix="") -> List[str]:
            lines = []
            keys = sorted(node.keys())
            for i, key in enumerate(keys):
                val = node[key]
                branch = "└── " if i == len(keys) - 1 else "├── "
                if val is None:
                    lines.append(prefix + branch + f"📄 {key}")
                else:
                    lines.append(prefix + branch + f"📁 {key}")
                    ext = "    " if i == len(keys) - 1 else "│   "
                    lines.extend(walk(val, prefix + ext))
            return lines

        return f"📁 {base.name}\n" + "\n".join(walk(root))

    # event queue helpers -------------------------------------------------

    def _queue_event(self, action: str, path: Path | tuple[Path, Path]) -> None:
        """Push a new :class:`FileEvent` onto the dispatch queue."""
        self._event_queue.put(FileEvent(action, path, datetime.now()))

    def _dispatch_loop(self) -> None:
        """Background thread dispatching queued events to callbacks."""
        while self.monitoring or not self._event_queue.empty():
            try:
                event = self._event_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            self.recent_events.append(event)
            if self.on_file_changed:
                try:
                    self.on_file_changed(event.action, event.path)
                except Exception as exc:
                    self.logger.error(f"Callback error: {exc}")

    def get_recent_events(self, limit: int = 10) -> List[FileEvent]:
        """Return up to *limit* recently dispatched events."""
        return list(self.recent_events)[-limit:]

    def _scan_watch_path(self, path: Path) -> None:
        """Analyze *path* for threats."""
        try:
            if path.is_file():
                try:
                    mtime = path.stat().st_mtime
                except Exception:
                    mtime = 0.0
                if self.file_mtimes.get(str(path)) == mtime and str(path) in self.file_hashes:
                    return
                risk = self.analyzer.analyze_file(path)
                if risk.level in ["high", "critical"]:
                    self._handle_threat(path, risk)
                digest = self._calculate_hash(path)
                self.file_hashes[str(path)] = digest
                self.file_mtimes[str(path)] = mtime
                if self.db:
                    try:
                        self.db.update_hash(str(path), digest, mtime)
                    except Exception:
                        pass
            elif path.is_dir():
                for file in path.rglob("*"):
                    if file.is_file():
                        try:
                            mtime = file.stat().st_mtime
                        except Exception:
                            mtime = 0.0
                        if self.file_mtimes.get(str(file)) == mtime and str(file) in self.file_hashes:
                            continue
                        risk = self.analyzer.analyze_file(file)
                        if risk.level in ["high", "critical"]:
                            self._handle_threat(file, risk)
                        digest = self._calculate_hash(file)
                        self.file_hashes[str(file)] = digest
                        self.file_mtimes[str(file)] = mtime
                        if self.db:
                            try:
                                self.db.update_hash(str(file), digest, mtime)
                            except Exception:
                                pass
        except Exception as exc:
            self.logger.error(f"Watchlist scan error for {path}: {exc}")

    # watchlist management -------------------------------------------------

    def add_watch_path(self, path: Path) -> None:
        """Add *path* to the aggressive scanning watchlist."""
        if path not in self.watchlist:
            mtime = 0.0
            try:
                mtime = path.stat().st_mtime
            except Exception:
                pass
            self.watchlist[path] = mtime
            if self.db:
                try:
                    self.db.add_watch_path(str(path))
                except Exception:
                    pass
            self.logger.info(f"Added to watchlist: {path}")

    def remove_watch_path(self, path: Path) -> None:
        """Remove *path* from the watchlist."""
        self.watchlist.pop(path, None)
        self.file_mtimes.pop(str(path), None)
        if self.db:
            try:
                self.db.remove_watch_path(str(path))
                self.db.delete_hash(str(path))
            except Exception:
                pass

    def list_watchlist(self) -> List[Path]:
        """Return the current watchlist."""
        return sorted(self.watchlist.keys())

    def set_watch_interval(self, seconds: float) -> None:
        """Update watchlist scanning interval."""
        if seconds > 0:
            self.watch_interval = float(seconds)

    def scan_watchlist_now(self) -> None:
        """Immediately scan all watchlisted paths."""
        paths = list(self.watchlist.keys())
        if not paths:
            return

        def _worker(p: Path) -> None:
            try:
                mtime = p.stat().st_mtime
            except Exception:
                mtime = 0.0
            if mtime != self.watchlist.get(p) or str(p) not in self.file_hashes:
                self.watchlist[p] = mtime
                self._scan_watch_path(p)
            else:
                # update in-memory mtimes when unchanged
                self.file_mtimes[str(p)] = mtime

        from concurrent.futures import ThreadPoolExecutor

        workers = min(4, os.cpu_count() or 1, len(paths))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            pool.map(_worker, paths)

    def auto_adjust_watch_interval(self) -> None:
        """Dynamically adjust the watch scan interval based on activity."""
        new_threats = self.stats.get("threats_detected", 0) - self._last_threat_count
        if new_threats > 0:
            self.watch_interval = max(5.0, self.watch_interval / 2)
            self._last_threat_count += new_threats
        elif self.watch_interval < self._default_interval:
            self.watch_interval = min(self._default_interval, self.watch_interval + 1)

    def _watchlist_scan(self) -> None:
        """Continuously scan watchlisted paths for threats."""
        while self.monitoring:
            self.scan_watchlist_now()
            self.auto_adjust_watch_interval()
            for _ in range(int(self.watch_interval)):
                if not self.monitoring:
                    break
                time.sleep(1)
            rem = self.watch_interval - int(self.watch_interval)
            if self.monitoring and rem > 0:
                time.sleep(rem)

    def get_stats(self) -> dict:
        """Return current monitoring statistics."""
        stats = dict(self.stats)
        if stats.get("start_time"):
            stats["uptime"] = (datetime.now() - stats["start_time"]).total_seconds()
        else:
            stats["uptime"] = 0
        stats["watchlist"] = len(self.watchlist)
        return stats
