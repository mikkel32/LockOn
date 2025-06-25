from utils.logger import logger
from .hasher import file_hash


class Scanner:
    def scan(self, path: str) -> str:
        digest = file_hash(path)
        logger.debug("Scanned %s hash=%s", path, digest)
        return digest
