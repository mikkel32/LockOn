from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from src.utils.logger import logger
from .analyzer import Analyzer
from .enforcer import Enforcer
from .intelligence import Intelligence


class MonitorHandler(FileSystemEventHandler):
    def __init__(self, analyzer: Analyzer, enforcer: Enforcer):
        self.analyzer = analyzer
        self.enforcer = enforcer

    def on_created(self, event):
        self.process(event)

    def on_modified(self, event):
        self.process(event)

    def process(self, event):
        logger.debug("Event %s on %s", event.event_type, event.src_path)
        if self.analyzer.analyze(event):
            self.enforcer.act_on_threat(event.src_path, self.analyzer.intelligence.rules)


class FileMonitor:
    def __init__(self, config):
        self.intelligence = Intelligence()
        self.analyzer = Analyzer(self.intelligence)
        self.enforcer = Enforcer(config)
        self.observer = Observer()
        self.config = config

    def start(self):
        handler = MonitorHandler(self.analyzer, self.enforcer)
        for path in self.config.get("monitor", {}).get("paths", ["."]):
            self.observer.schedule(handler, path, recursive=self.config.get("monitor", {}).get("recursive", True))
        logger.info("Starting monitor")
        self.observer.start()

    def stop(self):
        logger.info("Stopping monitor")
        self.observer.stop()
        self.observer.join()
