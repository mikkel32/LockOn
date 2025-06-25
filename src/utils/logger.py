"""Security Logger - Minimal logging utility used for tests"""
import logging
import threading
from pathlib import Path


class SecurityLogger:
    """Thread-safe singleton wrapper around Python's logging."""
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        self.log_dir = Path("data/logs")
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger("LockOn")
        self.logger.setLevel(logging.DEBUG)
        if not self.logger.handlers:
            file_handler = logging.FileHandler(self.log_dir / "security.log")
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
