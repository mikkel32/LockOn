import threading
from pathlib import Path
from utils.database import Database

def test_threadsafe_logging(tmp_path):
    db = Database(tmp_path / "db.sqlite")

    def worker():
        for i in range(10):
            db.log_event(f"file{i}", "created")

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    cur = db.conn.cursor()
    cur.execute("SELECT COUNT(*) FROM events")
    count = cur.fetchone()[0]
    db.close()
    assert count == 50


def test_fetch_methods(tmp_path):
    db = Database(tmp_path / "db.sqlite")
    db.log_event("foo.txt", "created")
    db.log_threat("foo.txt", "high", "malware")
    events = db.get_events()
    threats = db.get_threats()
    db.close()
    assert events[0][0] == "foo.txt"
    assert threats[0][0] == "foo.txt"
