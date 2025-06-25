#!/usr/bin/env python3
"""Debug server entry point for LockOn."""
import os
import sys
from pathlib import Path
import argparse

try:
    import debugpy
except ImportError:  # pragma: no cover - optional dependency
    print(
        "debugpy is required for remote debugging; install it to enable the debugger."
    )
    sys.exit(0)

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

import main  # noqa: E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="LockOn debug server")
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("LOCKON_DEBUG_PORT", 5678)),
        help="Port to expose for debugger",
    )
    return parser.parse_args(argv)


def main_debug(port: int) -> None:
    debugpy.listen(("0.0.0.0", port))
    print(f"Waiting for debugger attach on port {port}...")
    debugpy.wait_for_client()
    main.main()


if __name__ == "__main__":
    args = parse_args()
    main_debug(args.port)
