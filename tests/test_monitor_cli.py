import tempfile
import sys
import time
from pathlib import Path

from core.monitor_cli import LockOnCLI
import core.monitor_cli as monitor_cli


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

    cli._log_threat(tmp_path / "foo.txt", _Risk)
    cli.db.close()

    monitor_cli._print_events(db_file, 1)
    out = capsys.readouterr().out
    assert "foo.txt" in out

    monitor_cli._print_threats(db_file, 1)
    out = capsys.readouterr().out
    assert "high" in out


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

