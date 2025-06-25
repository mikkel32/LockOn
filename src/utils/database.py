import sqlite3
from pathlib import Path

DB_PATH = Path("data/database.db")


class Database:
    def __init__(self, path: Path = DB_PATH):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self._create_tables()

    def _create_tables(self):
        cur = self.conn.cursor()
        cur.execute(
            """CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT,
            action TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )"""
        )
        self.conn.commit()

    def log_event(self, path: str, action: str):
        cur = self.conn.cursor()
        cur.execute("INSERT INTO events(path, action) VALUES (?, ?)", (path, action))
        self.conn.commit()
