"""Command-line interface for LockOn monitoring."""
import argparse
import time
from pathlib import Path
import os

from utils.logger import SecurityLogger
from utils.config import load_config, ensure_config
from utils.database import Database
from core.monitor import FolderMonitor


class LockOnCLI:
    """Run ``FolderMonitor`` without the GUI."""

    def __init__(
        self,
        config_path: Path | None = None,
        folder: str | None = None,
        db_path: Path | None = None,
        debug: bool = False,
        debug_port: int = 5678,
    ) -> None:
        cfg_path = config_path or Path("config.yaml")
        ensure_config(cfg_path)
        self.config = load_config(cfg_path)
        log_cfg = self.config.get("logging", {})
        self.logger = SecurityLogger(
            Path(log_cfg.get("file", "data/logs/security.log")),
            log_cfg.get("level", "DEBUG"),
        )
        self.monitor = FolderMonitor()

        final_db = db_path or Path(
            self.config.get("database", {}).get("path", "data/database.db")
        )
        self.db = Database(final_db)
        self.debug = debug
        self.debug_port = debug_port

        self.monitor.on_file_changed = self._log_file_event
        self.monitor.on_threat_detected = self._log_threat

        folder_setting = folder or self.config.get("monitor", {}).get("paths", [None])[0]
        if folder_setting:
            self.monitor.set_target_folder(folder_setting)

    def run(self) -> None:
        """Start monitoring until interrupted."""
        if self.debug:
            try:
                import debugpy
            except ImportError:
                self.logger.error(
                    "debugpy is required for debugging. Install with `pip install debugpy`."
                )
            else:
                debugpy.listen(("0.0.0.0", self.debug_port))
                print(f"Waiting for debugger attach on port {self.debug_port}...")
                debugpy.wait_for_client()
        self.monitor.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Interrupted by user")
        finally:
            self.monitor.stop()
            self.db.close()

    def _log_file_event(self, action: str, path) -> None:
        """Callback to log file events into the database."""
        if isinstance(path, tuple):
            src, dest = path
            entry = f"{src} -> {dest}"
        else:
            entry = str(path)
        self.db.log_event(entry, action)

    def _log_threat(self, filepath, risk) -> None:
        """Callback to log detected threats."""
        self.db.log_threat(str(filepath), risk.level, risk.type)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="LockOn command-line utilities")
    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        help="Path to configuration file",
    )
    parser.add_argument(
        "--db",
        type=Path,
        help="Database file path",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="Start folder monitoring")
    run_p.add_argument(
        "-f",
        "--folder",
        type=str,
        help="Folder to monitor (overrides config)",
    )
    run_p.add_argument(
        "--debug",
        action="store_true",
        help="Wait for debugger attach on port 5678",
    )
    run_p.add_argument(
        "--debug-port",
        type=int,
        default=int(os.environ.get("LOCKON_DEBUG_PORT", 5678)),
        help="Debugger port",
    )

    events_p = sub.add_parser("events", help="Show recent filesystem events")
    events_p.add_argument("-n", "--limit", type=int, default=10)

    threats_p = sub.add_parser("threats", help="Show detected threats")
    threats_p.add_argument("-n", "--limit", type=int, default=10)

    return parser.parse_args(argv)


def _print_events(db: Path, limit: int) -> None:
    """Print recent filesystem events from the database."""
    with Database(db) as database:
        for path, action, ts in database.get_events(limit):
            print(f"{ts} {action:8} {path}")


def _print_threats(db: Path, limit: int) -> None:
    """Print recent detected threats from the database."""
    with Database(db) as database:
        for path, level, ttype, ts in database.get_threats(limit):
            print(f"{ts} {level:8} {ttype:10} {path}")


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)

    if args.command == "run":
        LockOnCLI(args.config, args.folder, args.db, args.debug, args.debug_port).run()
    else:
        cfg = load_config(args.config or Path("config.yaml"))
        db_path = Path(args.db or cfg.get("database", {}).get("path", "data/database.db"))
        if args.command == "events":
            _print_events(db_path, args.limit)
        elif args.command == "threats":
            _print_threats(db_path, args.limit)


if __name__ == "__main__":
    main()
