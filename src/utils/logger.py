"""Security Logger - Minimal logging utility used for tests"""
import logging
import threading
from pathlib import Path


class SecurityLogger:
    """Thread-safe singleton wrapper around Python's logging."""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls, log_file: Path | None = None, level: str = "DEBUG"):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
            cls._instance._initialize(log_file, level)
        return cls._instance

    def _initialize(self, log_file: Path | None, level: str) -> None:
        self.log_path = log_file or Path("data/logs/security.log")
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger("LockOn")
        self.logger.setLevel(getattr(logging, level.upper(), logging.DEBUG))

        # Clear existing handlers to allow reconfiguration
        for h in list(self.logger.handlers):
            self.logger.removeHandler(h)

        file_handler = logging.FileHandler(self.log_path)
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        file_handler.setFormatter(formatter)
        console = logging.StreamHandler()
        console.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console)

    def debug(self, msg, **kwargs):
        self.logger.debug(msg)

    def info(self, msg, **kwargs):
        self.logger.info(msg)

    def warning(self, msg, **kwargs):
        self.logger.warning(msg)

    def error(self, msg, **kwargs):
        self.logger.error(msg)

    def critical(self, msg, **kwargs):
        self.logger.critical(msg)

# Convenience logger instance for modules that expect a module-level `logger`.
logger = SecurityLogger()
