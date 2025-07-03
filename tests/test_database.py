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


def test_watchlist_methods(tmp_path):
    db = Database(tmp_path / "db.sqlite")
    p1 = str(tmp_path / "a")
    p2 = str(tmp_path / "b")
    db.add_watch_path(p1)
    db.add_watch_path(p2)
    watch = set(db.get_watchlist())
    assert watch == {p1, p2}
    db.remove_watch_path(p1)
    watch = set(db.get_watchlist())
    db.close()
    assert watch == {p2}


def test_export_csv(tmp_path):
    db = Database(tmp_path / "db.sqlite")
    db.log_event("foo.txt", "created")
    db.log_threat("foo.txt", "high", "mal")
    ev_csv = tmp_path / "events.csv"
    th_csv = tmp_path / "threats.csv"
    db.export_events_csv(ev_csv)
    db.export_threats_csv(th_csv)
    db.close()
    assert ev_csv.read_text().strip().splitlines()[0] == "path,action,timestamp"
    assert th_csv.read_text().strip().splitlines()[0] == "path,level,type,timestamp"


def test_stats_methods(tmp_path):
    db = Database(tmp_path / "db.sqlite")
    db.log_event("foo.txt", "created")
    db.log_threat("foo.txt", "high", "mal")
    db.add_watch_path("foo.txt")
    stats = db.get_stats()
    db.close()
    assert stats["events"] == 1
    assert stats["threats"] == 1
    assert stats["watchlist"] == 1
    assert "hashes" in stats


def test_hash_methods(tmp_path):
    db = Database(tmp_path / "db.sqlite")
    db.update_hash("a.txt", "123", 1.0)
    assert db.get_hash("a.txt") == ("123", 1.0)
    db.update_hash("a.txt", "abc", 2.0)
    assert db.get_hash("a.txt") == ("abc", 2.0)
    db.delete_hash("a.txt")
    assert db.get_hash("a.txt") is None
    db.close()
