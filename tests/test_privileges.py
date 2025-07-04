import time
import sys
from security.privileges import PrivilegeManager


def test_privilege_monitor(monkeypatch):
    calls = []

    class PM(PrivilegeManager):
        def ensure_active(self, privs, impersonate=True):
            calls.append(list(privs))
            return []

    pm = PM(auto_monitor=False)
    monkeypatch.setattr(sys, "platform", "win32")
    pm.start_monitor(["SeDebugPrivilege"], interval=0.05)
    time.sleep(0.12)
    pm.stop_monitor()
    assert calls


def test_privilege_verify_nonroot(monkeypatch):
    pm = PrivilegeManager()
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr("os.geteuid", lambda: 1000)
    assert pm.verify(["root"]) == ["root"]


def test_privilege_verify_root(monkeypatch):
    pm = PrivilegeManager()
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr("os.geteuid", lambda: 0)
    assert pm.verify(["root"]) == []


def test_posix_ensure_active(monkeypatch):
    pm = PrivilegeManager()
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr("os.geteuid", lambda: 1000)
    assert pm.ensure_active(["root"]) == ["root"]
    monkeypatch.setattr("os.geteuid", lambda: 0)
    assert pm.ensure_active(["root"]) == []


def test_is_elevated(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr("os.geteuid", lambda: 0)
    from security import privileges

    assert privileges.is_elevated() is True
    monkeypatch.setattr("os.geteuid", lambda: 1000)
    assert privileges.is_elevated() is False
