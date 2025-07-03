import importlib
import builtins
import time
from pathlib import Path

import pytest

import src.core.monitor as monitor


def test_polling_observer_fallback(monkeypatch, tmp_path):
    orig_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name.startswith("watchdog"):
            raise ModuleNotFoundError("watchdog")
        return orig_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    m = importlib.reload(monitor)
    assert m.WATCHDOG_AVAILABLE is False

    events = []

    class Handler(m.FileSystemEventHandler):
        def on_created(self, event):
            events.append(event.src_path)

    obs = m.Observer(interval=0.1)
    obs.schedule(Handler(), str(tmp_path), recursive=False)
    obs.start()
    (tmp_path / "foo.txt").write_text("hi")

    for _ in range(30):
        if events:
            break
        time.sleep(0.05)

    obs.stop()
    assert any("foo.txt" in e for e in events)

    monkeypatch.setattr(builtins, "__import__", orig_import)
    importlib.reload(monitor)
