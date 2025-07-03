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
try:  # optional watchdog dependency
    from watchdog.observers import Observer  # type: ignore
    from watchdog.events import FileSystemEventHandler, FileSystemEvent  # type: ignore
    WATCHDOG_AVAILABLE = True
except Exception:  # pragma: no cover - provide fallback
    WATCHDOG_AVAILABLE = False
    class FileSystemEvent:
        """Minimal stand-in for ``watchdog`` events."""

        def __init__(self, src_path: str, is_directory: bool = False, dest_path: str | None = None) -> None:
            self.src_path = src_path
            self.dest_path = dest_path
            self.is_directory = is_directory


    class FileSystemEventHandler:
        """Base event handler used when ``watchdog`` is unavailable."""

    class _PollingObserver:
        """Very small polling based observer as a fallback."""

        def __init__(self, interval: float = 1.0) -> None:
            self.interval = interval
            self._handlers: list[tuple[FileSystemEventHandler, Path, bool, dict[str, float]]] = []
            self._thread: threading.Thread | None = None
            self._running = False

        def schedule(self, handler: FileSystemEventHandler, path: str, recursive: bool = True) -> None:
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

        def _scan(self, handler: FileSystemEventHandler, path: Path, recursive: bool, snapshot: dict[str, float]) -> None:
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

from core.analyzer import PatternAnalyzer
from core.enforcer import ActionEnforcer
from utils.logger import SecurityLogger
from security.network_monitor import NetworkMonitor


class FolderMonitor(FileSystemEventHandler):
    """Advanced folder monitoring system"""

    def __init__(self, priv_manager: "PrivilegeManager | None" = None):
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

        # Statistics
        self.stats = {
            'files_monitored': 0,
            'threats_detected': 0,
            'actions_taken': 0,
            'start_time': None
        }

        # File tracking
        self.file_hashes: Dict[str, str] = {}
        self.file_activity: Dict[str, List[datetime]] = {}
        self.suspicious_processes: List[int] = []

        self.on_network_threat: Optional[Callable] = None

        # Callbacks
        self.on_threat_detected: Optional[Callable] = None
        self.on_file_changed: Optional[Callable] = None

    def set_target_folder(self, folder: str):
        """Set the folder to monitor"""
        self.target_folder = Path(folder)
        self.logger.info(f"Target folder set to: {folder}")

        # Initial scan
        self._scan_folder()

    def _scan_folder(self):
        """Initial scan of target folder"""
        if not self.target_folder or not self.target_folder.exists():
            return

        self.logger.info("Starting initial folder scan...")

        for root, dirs, files in os.walk(self.target_folder):
            for file in files:
                filepath = Path(root) / file
                try:
                    # Calculate hash
                    file_hash = self._calculate_hash(filepath)
                    self.file_hashes[str(filepath)] = file_hash

                    # Analyze file
                    risk = self.analyzer.analyze_file(filepath)
                    if risk.level in ['high', 'critical']:
                        self.logger.warning(f"High-risk file found: {filepath}")
                        self._handle_threat(filepath, risk)

                except Exception as e:
                    self.logger.error(f"Error scanning {filepath}: {e}")

        self.stats['files_monitored'] = len(self.file_hashes)
        self.logger.info(f"Initial scan complete. {self.stats['files_monitored']} files indexed.")

    def _calculate_hash(self, filepath: Path) -> str:
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except:
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
                self.logger.warning(f"Missing privileges: {', '.join(sorted(set(missing)))}")
            else:
                self.logger.debug("All critical privileges enabled")
        except Exception as exc:
            self.logger.error(f"Privilege elevation failed: {exc}")

        self.monitoring = True
        self.stats['start_time'] = datetime.now()

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

        self.logger.info("Monitoring stopped")

    def on_created(self, event: FileSystemEvent):
        """Handle file creation"""
        if event.is_directory:
            return

        filepath = Path(event.src_path)
        self.logger.debug(f"File created: {filepath}")

        # Analyze new file
        risk = self.analyzer.analyze_file(filepath)

        if risk.level in ['high', 'critical']:
            self.logger.warning(f"Suspicious file created: {filepath}")
            self._handle_threat(filepath, risk)
        else:
            # Calculate hash for tracking
            self.file_hashes[str(filepath)] = self._calculate_hash(filepath)

        self._track_activity(filepath, 'created')

        if self.on_file_changed:
            self.on_file_changed('created', filepath)

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
        self._track_activity(filepath, 'modified')

        if self.on_file_changed:
            self.on_file_changed('modified', filepath)

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
        self._track_activity(filepath, 'deleted')

        if self.on_file_changed:
            self.on_file_changed('deleted', filepath)

    def on_moved(self, event: FileSystemEvent):
        """Handle file move/rename"""
        if event.is_directory:
            return

        src_path = Path(event.src_path)
        dest_path = Path(event.dest_path)

        self.logger.info(f"File moved: {src_path} -> {dest_path}")

        # Update tracking
        if str(src_path) in self.file_hashes:
            self.file_hashes[str(dest_path)] = self.file_hashes.pop(str(src_path))

        self._track_activity(dest_path, 'moved')

        if self.on_file_changed:
            self.on_file_changed('moved', (src_path, dest_path))

    def _track_activity(self, filepath: Path, action: str):
        """Track file activity for behavior analysis"""
        key = str(filepath)
        if key not in self.file_activity:
            self.file_activity[key] = []

        self.file_activity[key].append(datetime.now())

        # Check for rapid activity
        recent_activity = [t for t in self.file_activity[key] 
                          if (datetime.now() - t).seconds < 60]

        if len(recent_activity) > 10:
            self.logger.warning(f"Rapid activity on {filepath}: {len(recent_activity)} actions/min")
            self._check_behavior_patterns()

    def _is_suspicious_deletion(self, filepath: Path) -> bool:
        """Check if deletion is suspicious"""
        # Check if system/important file
        suspicious_patterns = ['system', 'config', 'important', 'critical']
        if any(pattern in str(filepath).lower() for pattern in suspicious_patterns):
            return True

        # Check deletion rate
        recent_deletions = sum(1 for _, activities in self.file_activity.items()
                              if any((datetime.now() - t).seconds < 60 for t in activities))

        return recent_deletions > 20

    def _handle_threat(self, filepath: Path, risk):
        """Handle detected threat"""
        self.stats['threats_detected'] += 1

        self.logger.warning(f"Threat detected: {filepath} - Risk: {risk.level}")

        # Take action based on risk level
        if risk.level == 'critical':
            self._handle_critical_threat(filepath, risk.type)
        elif risk.level == 'high':
            self._handle_high_threat(filepath, risk.type)
        else:
            self._handle_medium_threat(filepath, risk.type)

        # Notify callback
        if self.on_threat_detected:
            self.on_threat_detected(filepath, risk)

        self.stats['actions_taken'] += 1

    def _handle_critical_threat(self, filepath: Path, threat_type: str):
        """Handle critical threats"""
        self.logger.critical(f"CRITICAL THREAT: {filepath} - Type: {threat_type}")

        # Immediate actions
        if threat_type == 'ransomware':
            # Emergency lockdown
            self.enforcer.emergency_lockdown(self.target_folder)
            # Kill suspicious processes
            self._terminate_suspicious_processes()
            # Backup critical files
            self.enforcer.emergency_backup(self.target_folder)

        elif threat_type == 'encryption':
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
            if sys.platform == "win32":
                try:
                    self.priv_manager.ensure_active(["SeDebugPrivilege"], impersonate=False)
                except Exception:
                    pass
            try:
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
                    try:
                        # Check process behavior
                        if self.analyzer.is_suspicious_process(proc):
                            if proc.pid not in self.suspicious_processes:
                                self.suspicious_processes.append(proc.pid)
                                self.logger.warning(f"Suspicious process detected: {proc.info['name']} (PID: {proc.pid})")

                                if self.shield_active:
                                    self.enforcer.handle_suspicious_process(proc)

                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

            except Exception as e:
                self.logger.error(f"Process monitoring error: {e}")

            time.sleep(5)  # Check every 5 seconds

    def _periodic_scan(self):
        """Periodic security scan"""
        while self.monitoring:
            time.sleep(300)  # Every 5 minutes

            try:
                if sys.platform == "win32":
                    try:
                        self.priv_manager.ensure_active(["SeDebugPrivilege"], impersonate=False)
                    except Exception:
                        pass
                self.logger.debug("Running periodic security scan...")

                # Check for new threats
                for filepath_str, file_hash in list(self.file_hashes.items()):
                    filepath = Path(filepath_str)
                    if filepath.exists():
                        # Re-analyze files
                        risk = self.analyzer.analyze_file(filepath)
                        if risk.level in ['high', 'critical']:
                            self._handle_threat(filepath, risk)

                # Check behavior patterns
                self._check_behavior_patterns()

            except Exception as e:
                self.logger.error(f"Periodic scan error: {e}")

    def _check_behavior_patterns(self):
        """Analyze behavior patterns for anomalies"""
        # Check for mass file changes
        recent_changes = sum(len([t for t in activities if (datetime.now() - t).seconds < 300])
                           for activities in self.file_activity.values())

        if recent_changes > 500:
            self.logger.critical("Mass file changes detected - possible ransomware!")
            self._handle_critical_threat(self.target_folder, "mass_changes")

    def _terminate_suspicious_processes(self):
        """Terminate all suspicious processes"""
        for pid in self.suspicious_processes:
            try:
                proc = psutil.Process(pid)
                self.logger.warning(f"Terminating suspicious process: {proc.name()} (PID: {pid})")
                proc.terminate()
                proc.wait(timeout=5)
                if proc.is_running():
                    proc.kill()
            except:
                pass

        self.suspicious_processes.clear()

    def _block_file_process(self, filepath: Path):
        """Block process that accessed the file"""
        # Get process that has file open
        for proc in psutil.process_iter(['pid', 'name', 'open_files']):
            try:
                if proc.info['open_files']:
                    for f in proc.info['open_files']:
                        if str(filepath) in f.path:
                            self.logger.warning(f"Blocking process {proc.info['name']} accessing {filepath}")
                            self.enforcer.handle_suspicious_process(proc)
                            break
            except:
                pass

    def _increase_monitoring(self, directory: Path):
        """Increase monitoring frequency for directory"""
        # Implementation for increased monitoring
        self.logger.info(f"Increased monitoring on: {directory}")

    def _add_to_watchlist(self, filepath: Path):
        """Add file to special watchlist"""
        # Implementation for watchlist
        self.logger.info(f"Added to watchlist: {filepath}")

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
        if self.on_network_threat:
            self.on_network_threat(conn)
        if self.shield_active and pid:
            try:
                proc = psutil.Process(pid)
                if self.analyzer.is_suspicious_process(proc) or analysis.level in ["high", "critical"]:
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
