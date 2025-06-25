import time
from src.utils.logger import logger
from .monitor import FileMonitor
from src.utils.database import Database


class MonitorCLI:
    def __init__(self, config):
        self.monitor = FileMonitor(config)
        self.db = Database()

    def run(self):
        try:
            self.monitor.start()
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Interrupted by user")
        finally:
            self.monitor.stop()
