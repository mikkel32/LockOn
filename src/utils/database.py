import sqlite3
import threading
from pathlib import Path

DB_PATH = Path("data/database.db")


class Database:
    def __init__(self, path: Path = DB_PATH):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self._lock = threading.Lock()
        self._create_tables()

    # allow use as context manager
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def _create_tables(self) -> None:
        """Create database tables if they don't exist."""
        cur = self.conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT,
                action TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT,
                level TEXT,
                type TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        self.conn.commit()

    def log_event(self, path: str, action: str) -> None:
        """Record a filesystem event."""
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(
                "INSERT INTO events(path, action) VALUES (?, ?)", (path, action)
            )
            self.conn.commit()

    def log_threat(self, path: str, level: str, threat_type: str) -> None:
        """Record a detected threat."""
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(
                "INSERT INTO threats(path, level, type) VALUES (?, ?, ?)",
                (path, level, threat_type),
            )
            self.conn.commit()

    def close(self) -> None:
        """Close the database connection."""
        with self._lock:
            self.conn.close()

    def get_events(self, limit: int | None = None):
        """Return recent filesystem events."""
        with self._lock:
            cur = self.conn.cursor()
            query = "SELECT path, action, timestamp FROM events ORDER BY id DESC"
            if limit:
                query += " LIMIT ?"
                cur.execute(query, (limit,))
            else:
                cur.execute(query)
            return cur.fetchall()

    def get_threats(self, limit: int | None = None):
        """Return recent threats."""
        with self._lock:
            cur = self.conn.cursor()
            query = "SELECT path, level, type, timestamp FROM threats ORDER BY id DESC"
            if limit:
                query += " LIMIT ?"
                cur.execute(query, (limit,))
            else:
                cur.execute(query)
            return cur.fetchall()
