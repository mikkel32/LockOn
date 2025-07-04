import sys
import runpy
from pathlib import Path

import setup


def _run_setup(args, monkeypatch):
    monkeypatch.setattr(setup, "show_setup_banner", lambda: None)
    monkeypatch.setattr(setup, "check_python_version", lambda: None)
    sys.argv = ["setup.py", *args]
    runpy.run_path(Path(setup.__file__), run_name="__main__")


def test_vm_subcommand_forwards(monkeypatch):
    called = {}
    def fake_main(argv=None):
        called["args"] = argv
    import scripts.manage_vm as manage_vm
    monkeypatch.setattr(manage_vm, "main", fake_main)
    _run_setup(["vm", "start", "--port", "6000"], monkeypatch)
    assert called["args"] == ["start", "--port", "6000"]
