import sqlite3
import threading
from pathlib import Path

from .paths import resource_path

DB_PATH = resource_path("data", "database.db")


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
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS watchlist (
                path TEXT PRIMARY KEY
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS hashes (
                path TEXT PRIMARY KEY,
                hash TEXT,
                mtime REAL
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

    # watchlist helpers -------------------------------------------------

    def add_watch_path(self, path: str) -> None:
        """Store *path* in the watchlist table."""
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(
                "INSERT OR IGNORE INTO watchlist(path) VALUES (?)",
                (path,),
            )
            self.conn.commit()

    def remove_watch_path(self, path: str) -> None:
        """Remove *path* from the watchlist table."""
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("DELETE FROM watchlist WHERE path = ?", (path,))
            self.conn.commit()

    def get_watchlist(self) -> list[str]:
        """Return all watchlisted paths."""
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("SELECT path FROM watchlist")
            return [row[0] for row in cur.fetchall()]

    # hash helpers ------------------------------------------------------

    def update_hash(self, path: str, digest: str, mtime: float) -> None:
        """Insert or update a file hash entry."""
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(
                "INSERT OR REPLACE INTO hashes(path, hash, mtime) VALUES (?, ?, ?)",
                (path, digest, mtime),
            )
            self.conn.commit()

    def get_hash(self, path: str) -> tuple[str, float] | None:
        """Return stored hash and mtime for *path* if present."""
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("SELECT hash, mtime FROM hashes WHERE path = ?", (path,))
            row = cur.fetchone()
            if row:
                return row[0], float(row[1])
            return None

    def delete_hash(self, path: str) -> None:
        """Remove hash record for *path*."""
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("DELETE FROM hashes WHERE path = ?", (path,))
            self.conn.commit()

    def load_hashes(self) -> dict[str, tuple[str, float]]:
        """Return all stored hashes as a mapping."""
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("SELECT path, hash, mtime FROM hashes")
            return {row[0]: (row[1], float(row[2])) for row in cur.fetchall()}

    # csv export helpers -------------------------------------------------

    def export_events_csv(self, csv_path: Path, limit: int | None = None) -> None:
        """Write recent events to *csv_path*."""
        import csv

        rows = self.get_events(limit)
        with open(csv_path, "w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["path", "action", "timestamp"])
            writer.writerows(rows)

    def export_threats_csv(self, csv_path: Path, limit: int | None = None) -> None:
        """Write recent threats to *csv_path*."""
        import csv

        rows = self.get_threats(limit)
        with open(csv_path, "w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["path", "level", "type", "timestamp"])
            writer.writerows(rows)

    # statistics helpers -------------------------------------------------

    def get_event_count(self) -> int:
        """Return total number of events logged."""
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("SELECT COUNT(*) FROM events")
            return int(cur.fetchone()[0])

    def get_threat_count(self) -> int:
        """Return total number of threats logged."""
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("SELECT COUNT(*) FROM threats")
            return int(cur.fetchone()[0])

    def get_watchlist_count(self) -> int:
        """Return number of entries in the watchlist."""
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("SELECT COUNT(*) FROM watchlist")
            return int(cur.fetchone()[0])

    def get_hash_count(self) -> int:
        """Return number of stored file hashes."""
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("SELECT COUNT(*) FROM hashes")
            return int(cur.fetchone()[0])

    def get_stats(self) -> dict[str, int]:
        """Return statistics summary of the database."""
        return {
            "events": self.get_event_count(),
            "threats": self.get_threat_count(),
            "watchlist": self.get_watchlist_count(),
            "hashes": self.get_hash_count(),
        }
