"""Entry point for LockOn monitoring application."""

from src.core.monitor_cli import MonitorCLI
from src.utils.config import load_config
from src.utils.logger import setup_logging


def main():
    config = load_config()
    setup_logging(config)
    cli = MonitorCLI(config)
    cli.run()


if __name__ == "__main__":
    main()
