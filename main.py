#!/usr/bin/env python3
"""
Lock On - Intelligent Folder Security System
Main entry point with display detection
"""
import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))


def main():
    """Initialize and run Lock On"""
    # Check for display availability
    if not os.environ.get('DISPLAY') and sys.platform != 'win32':
        print("🔒 Lock On - Running in monitoring mode (no display)")
        from core.monitor_cli import LockOnCLI
        app = LockOnCLI()
        app.run()
    else:
        try:
            from ui.app import LockOnApp
            print("🔒 Lock On - Initializing security system...")
            app = LockOnApp()
            app.run()
        except Exception as e:
            if "display" in str(e).lower():
                print("🔒 Display error - falling back to monitoring mode")
                from core.monitor_cli import LockOnCLI
                app = LockOnCLI()
                app.run()
            else:
                raise e


if __name__ == "__main__":
    main()
