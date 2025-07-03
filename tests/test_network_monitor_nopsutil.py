import importlib
import sys
from types import SimpleNamespace

from security.network_monitor import NetworkMonitor
from utils import psutil_compat

class DummyPM:
    def ensure_active(self, privs, impersonate=True):
        return []

def test_network_monitor_fallback(monkeypatch):
    monkeypatch.setitem(sys.modules, 'psutil', None)
    importlib.reload(psutil_compat)
    nm_mod = importlib.reload(importlib.import_module('security.network_monitor'))
    def fake_net_connections(kind='inet'):
        Addr = SimpleNamespace
        return [SimpleNamespace(raddr=Addr(ip='1.2.3.4', port=4444), pid=1)]
    monkeypatch.setattr(psutil_compat.psutil, 'net_connections', fake_net_connections, raising=False)
    nm = nm_mod.NetworkMonitor({'suspicious_ports':[4444]}, priv_manager=DummyPM())
    results = nm.check_now()
    assert len(results) == 1
