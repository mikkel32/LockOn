from pathlib import Path
import sys
import pytest
from core.enforcer import ActionEnforcer


def test_quarantine_restore(tmp_path):
    enforcer = ActionEnforcer(tmp_path / "q")
    f = tmp_path / "mal.txt"
    f.write_text("data")
    enforcer.quarantine_file(f)
    qfile = enforcer.quarantine_manager.directory / f.name
    assert qfile.exists() and not f.exists()
    enforcer.restore_file(f)
    assert f.exists() and not qfile.exists()


def test_quarantine_privilege_calls(monkeypatch, tmp_path):
    calls = []

    class FakePM:
        def ensure(self, privs, impersonate=True):
            calls.append(list(privs))
            return []

    monkeypatch.setattr(sys, "platform", "win32")
    qm = ActionEnforcer(tmp_path / "q", priv_manager=FakePM())
    f = tmp_path / "file.txt"
    f.write_text("x")
    qm.quarantine_file(f)
    qm.restore_file(f)

    assert ["SeBackupPrivilege"] in calls
    assert ["SeRestorePrivilege"] in calls


def test_privilege_error(monkeypatch, tmp_path):
    class FakePM:
        def ensure(self, privs, impersonate=True):
            return list(privs)

    monkeypatch.setattr(sys, "platform", "win32")
    enf = ActionEnforcer(tmp_path / "q", priv_manager=FakePM())
    f = tmp_path / "mal.txt"
    f.write_text("data")
    with pytest.raises(PermissionError):
        enf.quarantine_file(f)
