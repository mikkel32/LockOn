"""Command-line interface for LockOn monitoring."""
import argparse
import time
from pathlib import Path
import os

from utils.logger import SecurityLogger
from utils import helpers
from utils.threat import ThreatSummary
from utils.config import load_config, ensure_config
from utils.database import Database
from utils.paths import resource_path
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
        watch_interval: float | None = None,
    ) -> None:
        cfg_path = config_path or resource_path("config.yaml")
        ensure_config(cfg_path)
        self.config = load_config(cfg_path)
        log_cfg = self.config.get("logging", {})
        log_path = Path(log_cfg.get("file", "data/logs/security.log"))
        self.logger = SecurityLogger(
            resource_path(*log_path.parts),
            log_cfg.get("level", "DEBUG"),
        )
        db_conf = self.config.get("database", {}).get("path", "data/database.db")
        conf_parts = Path(db_conf).parts
        final_db = db_path or resource_path(*conf_parts)
        self.db = Database(final_db)

        mcfg = self.config.get("monitor", {})
        interval = float(watch_interval or mcfg.get("watch_interval", 30))
        watchlist = [Path(p) for p in mcfg.get("watchlist", [])]
        self.monitor = FolderMonitor(
            watch_interval=interval, watchlist=watchlist, db=self.db
        )

        for p in self.db.get_watchlist():
            self.monitor.add_watch_path(Path(p))
        self.debug = debug
        self.debug_port = debug_port

        self.monitor.on_network_threat = self._log_network_threat
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
        with self.monitor, self.db:
            self.monitor.start()
            if not self.monitor.monitoring:
                self.logger.error("Monitoring failed to start")
                return
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                self.logger.info("Interrupted by user")

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
        summary = ThreatSummary.from_detection(filepath, risk)
        self.db.log_threat(
            str(filepath),
            summary.level,
            summary.type,
            summary.details,
        )
        print(summary.format(color=True))

    def _log_network_threat(self, conn) -> None:
        try:
            entry = f"{conn.pid}:{conn.raddr.ip}:{conn.raddr.port}"
        except Exception:
            entry = str(conn)
        self.db.log_threat(entry, "high", "network", None)


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
    run_p.add_argument(
        "--watch-interval",
        type=float,
        help="Watchlist scan interval in seconds",
    )

    events_p = sub.add_parser("events", help="Show recent filesystem events")
    events_p.add_argument("-n", "--limit", type=int, default=10)

    threats_p = sub.add_parser("threats", help="Show detected threats")
    threats_p.add_argument("-n", "--limit", type=int, default=10)

    export_p = sub.add_parser("export", help="Export logs to CSV")
    export_p.add_argument("table", choices=["events", "threats"])
    export_p.add_argument("csv_file", type=Path)
    export_p.add_argument("-n", "--limit", type=int, default=None)

    tree_p = sub.add_parser("tree", help="Print monitored file tree")
    tree_p.add_argument("-f", "--folder", required=True)

    watch_p = sub.add_parser("watch", help="Manage watchlist")
    watch_p.add_argument("action", choices=["add", "remove", "list", "scan"])
    watch_p.add_argument("path", nargs="?")

    sub.add_parser("stats", help="Show database statistics")

    return parser.parse_args(argv)


def _print_events(db: Path, limit: int) -> None:
    """Print recent filesystem events from the database."""
    with Database(db) as database:
        for path, action, ts in database.get_events(limit):
            print(f"{ts} {action:8} {path}")


def _print_threats(db: Path, limit: int) -> None:
    """Print recent detected threats from the database."""
    with Database(db) as database:
        rows = database.get_threats(limit, with_details=True)
        for path, level, ttype, details, ts in rows:
            summary = ThreatSummary.from_db_row(path, level, ttype, details)
            msg = summary.format(color=True)
            print(f"{ts} {msg}")


def _print_tree(folder: str, config: Path | None, db: Path | None) -> None:
    """Print monitored file tree for *folder*."""
    cli = LockOnCLI(config, folder, db)
    cli.monitor.scan_now()
    tree = cli.monitor.build_file_tree()
    cli.db.close()
    print(tree)


def _print_stats(db: Path) -> None:
    """Print summary statistics from the database."""
    with Database(db) as database:
        stats = database.get_stats()
    print(f"Events: {stats['events']}")
    print(f"Threats: {stats['threats']}")
    print(f"Watchlist: {stats['watchlist']}")
    if 'hashes' in stats:
        print(f"Hashes: {stats['hashes']}")


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)

    if args.command == "run":
        LockOnCLI(
            args.config,
            args.folder,
            args.db,
            args.debug,
            args.debug_port,
            args.watch_interval,
        ).run()
    else:
        cfg = load_config(args.config or resource_path("config.yaml"))
        db_conf = cfg.get("database", {}).get("path", "data/database.db")
        db_path = resource_path(*Path(args.db or db_conf).parts)
        if args.command == "events":
            _print_events(db_path, args.limit)
        elif args.command == "threats":
            _print_threats(db_path, args.limit)
        elif args.command == "export":
            with Database(db_path) as database:
                if args.table == "events":
                    database.export_events_csv(args.csv_file, args.limit)
                else:
                    database.export_threats_csv(args.csv_file, args.limit)
            print(f"Exported {args.table} to {args.csv_file}")
        elif args.command == "watch":
            cli = LockOnCLI(args.config, None, args.db)
            if args.action == "list":
                for p in cli.db.get_watchlist():
                    print(p)
            elif args.action == "add" and args.path:
                cli.monitor.add_watch_path(Path(args.path))
                cli.monitor.scan_watchlist_now()
                print(f"Added to watchlist: {args.path}")
            elif args.action == "remove" and args.path:
                cli.monitor.remove_watch_path(Path(args.path))
                print(f"Removed from watchlist: {args.path}")
            elif args.action == "scan":
                cli.monitor.scan_watchlist_now()
                print("Watchlist scanned")
        elif args.command == "tree":
            _print_tree(args.folder, args.config, args.db)
        elif args.command == "stats":
            _print_stats(db_path)


if __name__ == "__main__":
    main()
