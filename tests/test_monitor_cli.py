import tempfile
import sys
import time
from pathlib import Path

from core.monitor_cli import LockOnCLI
import core.monitor_cli as monitor_cli
from utils.database import Database


def test_custom_db_path(tmp_path):
    cfg = tmp_path / "cfg.yaml"
    db_file = tmp_path / "events.sqlite"
    cfg.write_text(f"database:\n  path: {db_file}\n")

    cli = LockOnCLI(cfg)
    cli._log_file_event("created", tmp_path / "foo.txt")
    cli.db.close()

    assert db_file.exists()
    with open(db_file, "rb") as f:
        assert f.read(16)  # simple check that file not empty


def test_cli_arguments_override(tmp_path):
    db_file = tmp_path / "events.sqlite"
    cli = LockOnCLI(None, folder=str(tmp_path), db_path=db_file)
    cli._log_file_event("created", tmp_path / "foo.txt")
    cli.db.close()
    assert db_file.exists()


def test_parse_debug_flag():
    args = monitor_cli._parse_args(["run", "--debug", "--debug-port", "6000"])
    assert args.command == "run"
    assert args.debug is True
    assert args.debug_port == 6000


def test_print_helpers(tmp_path, capsys):
    db_file = tmp_path / "db.sqlite"
    cli = LockOnCLI(None, folder=str(tmp_path), db_path=db_file)
    cli._log_file_event("created", tmp_path / "foo.txt")

    class _Risk:
        level = "high"
        type = "test"
        details = {"snippets": [{"text": "snippet1", "line": 1}, {"text": "snippet2", "line": 2}]}

    cli._log_threat(tmp_path / "foo.txt", _Risk)
    cli.db.close()

    monitor_cli._print_events(db_file, 1)
    out = capsys.readouterr().out
    assert "foo.txt" in out

    monitor_cli._print_threats(db_file, 1)
    out = capsys.readouterr().out
    assert "high" in out
    assert "snippet1" in out
    assert "snippet2" in out
    assert "line 1" in out
    assert "line 2" in out


def test_custom_logger_path(tmp_path):
    cfg = tmp_path / "cfg.yaml"
    log_file = tmp_path / "app.log"
    cfg.write_text(f"logging:\n  file: {log_file}\n  level: INFO\n")

    cli = LockOnCLI(cfg)
    cli.logger.info("logtest")

    assert log_file.exists()


def test_lockoncli_debug_port(monkeypatch, tmp_path):
    args = monitor_cli._parse_args(["run", "--debug", "--debug-port", "6001"])
    captured = {}

    class FakeDebugPy:
        def listen(self, addr):
            captured["addr"] = addr

        def wait_for_client(self):
            captured["wait"] = True

    monkeypatch.setitem(sys.modules, "debugpy", FakeDebugPy())
    cli = LockOnCLI(None, folder=str(tmp_path), debug=args.debug, debug_port=args.debug_port)
    monkeypatch.setattr(cli.monitor, "start", lambda: None)
    monkeypatch.setattr(cli.monitor, "stop", lambda: None)
    monkeypatch.setattr(cli.db, "close", lambda: None)
    monkeypatch.setattr(time, "sleep", lambda x: (_ for _ in ()).throw(KeyboardInterrupt))

    cli.run()
    assert captured["addr"] == ("0.0.0.0", 6001)


def test_cli_missing_folder(monkeypatch, tmp_path):
    folder = tmp_path / "missing"
    cli = LockOnCLI(None, folder=str(folder))
    monkeypatch.setattr(time, "sleep", lambda x: (_ for _ in ()).throw(AssertionError("sleep called")))
    cli.run()


def test_watch_interval_override(tmp_path):
    args = monitor_cli._parse_args([
        "run",
        "--watch-interval",
        "5",
        "--folder",
        str(tmp_path),
    ])
    assert args.watch_interval == 5
    cli = LockOnCLI(None, folder=str(tmp_path), watch_interval=args.watch_interval)
    assert cli.monitor.watch_interval == 5


def test_watch_subcommands(tmp_path, capsys):
    cfg = tmp_path / "cfg.yaml"
    target = tmp_path / "mon"
    target.mkdir()
    db_file = tmp_path / "watch.sqlite"
    cfg.write_text(
        f"monitor:\n  paths: ['{target}']\n  recursive: true\n" f"database:\n  path: {db_file}\n"
    )

    monitor_cli.main(["-c", str(cfg), "watch", "add", str(target / "foo.txt")])
    monitor_cli.main(["-c", str(cfg), "watch", "list"])
    monitor_cli.main(["-c", str(cfg), "watch", "scan"])
    out = capsys.readouterr().out.strip().splitlines()
    assert str(target / "foo.txt") in out[-2]


def test_export_command(tmp_path):
    db = Database(tmp_path / "db.sqlite")
    db.log_event("foo.txt", "created")
    db.log_threat("foo.txt", "high", "test")
    db.close()
    ev_csv = tmp_path / "ev.csv"
    th_csv = tmp_path / "th.csv"
    monitor_cli.main(["--db", str(tmp_path / "db.sqlite"), "export", "events", str(ev_csv)])
    monitor_cli.main(["--db", str(tmp_path / "db.sqlite"), "export", "threats", str(th_csv), "-n", "1"])
    assert ev_csv.exists()
    assert th_csv.exists()


def test_cli_db_logging(tmp_path):
    folder = tmp_path / "mon"
    folder.mkdir()
    cli = LockOnCLI(None, folder=str(folder), db_path=tmp_path / "db.sqlite")
    cli.monitor.start()
    (folder / "evil.exe").write_bytes(b"MZ\x90\x00\x03")
    for _ in range(20):
        if cli.db.get_events(1) and cli.db.get_threats(1):
            break
        time.sleep(0.1)
    cli.monitor.stop()
    assert cli.db.get_events(1)
    assert cli.db.get_threats(1)
    cli.db.close()


def test_tree_command(tmp_path, capsys):
    folder = tmp_path / "mon"
    folder.mkdir()
    (folder / "demo.txt").write_text("hi")
    monitor_cli.main([
        "--db",
        str(tmp_path / "db.sqlite"),
        "tree",
        "-f",
        str(folder),
    ])
    out = capsys.readouterr().out
    assert "demo.txt" in out


def test_stats_command(tmp_path, capsys):
    db = Database(tmp_path / "db.sqlite")
    db.log_event("foo", "created")
    db.log_threat("foo", "high", "mal")
    db.add_watch_path("foo")
    db.close()

    monitor_cli.main(["--db", str(tmp_path / "db.sqlite"), "stats"])
    out = capsys.readouterr().out
    assert "Events: 1" in out
    assert "Threats: 1" in out
    assert "Watchlist: 1" in out

