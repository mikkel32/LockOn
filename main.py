#!/usr/bin/env python3

"""Main entry point for the Lock On security suite.

This script detects whether a graphical display is available and starts the
appropriate interface.  The command-line interface can be triggered
explicitly with ``--cli`` or the ``LOCKON_CLI=1`` environment variable.  The
configuration file path may also be overridden via ``--config`` or the
``LOCKON_CONFIG`` environment variable.
"""

import sys
import os
import argparse
from pathlib import Path

# Ensure ``src`` is always importable regardless of the working directory
SRC_PATH = Path(__file__).parent / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))


def _has_display() -> bool:
    """Return ``True`` if a graphical display is available."""
    if sys.platform == "win32":
        return True
    display = os.environ.get("DISPLAY")
    if not display:
        return False
    try:  # Verify that Tk can actually connect to the display
        import tkinter

        root = tkinter.Tk()
        root.destroy()
        return True
    except Exception:
        return False


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(description="Lock On security suite")
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print application version and exit",
    )
    parser.add_argument(
        "--show-config",
        action="store_true",
        help="Print the resolved configuration path and exit",
    )
    parser.add_argument(
        "--init-config",
        action="store_true",
        help="Create a default configuration file and exit",
    )
    parser.add_argument(
        "--cli",
        action="store_true",
        help="Force command-line interface",
    )
    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        help="Configuration file path",
    )
    parser.add_argument("--db", type=Path, help="Database path for CLI mode")
    parser.add_argument(
        "-f",
        "--folder",
        type=str,
        help="Folder to monitor in CLI mode",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Wait for debugger attach in CLI mode",
    )
    parser.add_argument(
        "--debug-port",
        type=int,
        default=int(os.environ.get("LOCKON_DEBUG_PORT", 5678)),
        help="Debugger port for CLI mode",
    )
    parser.add_argument(
        "--watch-interval",
        type=float,
        default=float(os.environ.get("LOCKON_WATCH_INTERVAL", 0)),
        help="Watchlist scan interval for CLI mode",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    """Initialize and run Lock On."""
    args = _parse_args(argv)

    if args.version:
        from src import __version__

        print(__version__)
        return

    if args.show_config:
        cfg = args.config or os.environ.get("LOCKON_CONFIG", "config.yaml")
        print(Path(cfg).expanduser().resolve())
        return

    if args.init_config:
        from utils.config import ensure_config

        cfg = Path(args.config or os.environ.get("LOCKON_CONFIG", "config.yaml"))
        ensure_config(cfg)
        print(f"Initialized configuration at {cfg}")
        return

    try:
        from security.privileges import PrivilegeManager, ALL_PRIVILEGES

        PrivilegeManager(auto_monitor=True).ensure(ALL_PRIVILEGES)
    except Exception as exc:  # pragma: no cover - privilege errors are not fatal
        print(f"Privilege initialization failed: {exc}")

    if args.config:
        os.environ["LOCKON_CONFIG"] = str(args.config)

    force_cli = args.cli or os.environ.get("LOCKON_CLI") == "1"
    if force_cli or not _has_display():
        print("🔒 Lock On - Running in monitoring mode")
        from core.monitor_cli import LockOnCLI

        LockOnCLI(
            config_path=args.config,
            folder=args.folder,
            db_path=args.db,
            debug=args.debug,
            debug_port=args.debug_port,
            watch_interval=args.watch_interval or None,
        ).run()
        return

    try:
        from ui.app import LockOnApp
    except ModuleNotFoundError as exc:
        print(f"UI dependencies missing: {exc}")
        print("Run `pip install -r requirements.txt` to install them")
        from core.monitor_cli import LockOnCLI

        LockOnCLI(
            config_path=args.config,
            folder=args.folder,
            db_path=args.db,
            debug=args.debug,
            debug_port=args.debug_port,
            watch_interval=args.watch_interval or None,
        ).run()
        return
    except Exception as exc:
        if "display" in str(exc).lower():
            print("🔒 Display error - falling back to monitoring mode")
            from core.monitor_cli import LockOnCLI

            LockOnCLI(
                config_path=args.config,
                folder=args.folder,
                db_path=args.db,
                debug=args.debug,
                debug_port=args.debug_port,
                watch_interval=args.watch_interval or None,
            ).run()
            return
        raise

    print("🔒 Lock On - Initializing security system...")
    LockOnApp().run()


if __name__ == "__main__":
    main(sys.argv[1:])
