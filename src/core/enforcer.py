from src.security.quarantine import QuarantineManager
from src.utils.logger import logger


class Enforcer:
    def __init__(self, config):
        self.quarantine = QuarantineManager()
        self.config = config

    def act_on_threat(self, path: str, rules: dict):
        if rules.get("quarantine_on_detect"):
            logger.info("Quarantining %s", path)
            self.quarantine.quarantine(path)
