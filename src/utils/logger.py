import logging
from pathlib import Path

logger = logging.getLogger("LockOn")


def setup_logging(config):
    cfg = config.get("logging", {})
    log_file = Path(cfg.get("file", "app.log"))
    log_file.parent.mkdir(parents=True, exist_ok=True)
    level = getattr(logging, cfg.get("level", "INFO").upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.FileHandler(log_file), logging.StreamHandler()]
    )
    logger.debug("Logging configured")
