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
