import unittest
import sys
import time
from types import SimpleNamespace

from security.network_monitor import NetworkMonitor

class TestNetworkMonitor(unittest.TestCase):
    def test_suspicious_connection_detection(self):
        patterns = {"suspicious_ports": [4444], "suspicious_ips": ["1.2.3."]}
        nm = NetworkMonitor(patterns)

        Addr = SimpleNamespace
        conn = SimpleNamespace(raddr=Addr(ip="1.2.3.4", port=4444), pid=1234)

        def fake_net_connections(kind="inet"):
            return [conn]

        from utils.psutil_compat import psutil
        orig = psutil.net_connections
        psutil.net_connections = fake_net_connections
        try:
            results = nm.check_now()
            self.assertEqual(len(results), 1)
            self.assertIs(results[0], conn)
        finally:
            psutil.net_connections = orig

    def test_analyze_connection(self):
        from core.analyzer import PatternAnalyzer

        pa = PatternAnalyzer()
        res = pa.analyze_connection("10.0.0.5", 4444)
        self.assertEqual(res.level, "high")

    def test_detection_via_analyzer(self):
        from core.analyzer import PatternAnalyzer

        analyzer = PatternAnalyzer()
        nm = NetworkMonitor({}, analyzer=analyzer)

        Addr = SimpleNamespace
        conn = SimpleNamespace(raddr=Addr(ip="10.0.0.5", port=4444), pid=42)

        def fake_net_connections(kind="inet"):
            return [conn]

        from utils.psutil_compat import psutil
        orig = psutil.net_connections
        psutil.net_connections = fake_net_connections
        try:
            results = nm.check_now()
            self.assertEqual(len(results), 1)
            self.assertIs(results[0], conn)
        finally:
            psutil.net_connections = orig

    def test_reacquire_privilege(self):
        class FakePM:
            def __init__(self):
                self.calls = []

            def ensure_active(self, privs, impersonate=True):
                self.calls.append(list(privs))
                return []

        pm = FakePM()
        nm = NetworkMonitor({}, priv_manager=pm)

        def fake_net_connections(kind="inet"):
            return []

        from utils.psutil_compat import psutil
        orig = psutil.net_connections
        psutil.net_connections = fake_net_connections
        try:
            nm.check_now()
            if sys.platform == "win32":
                self.assertIn(["SeDebugPrivilege"], pm.calls)
            else:
                self.assertEqual(pm.calls, [])
        finally:
            psutil.net_connections = orig

    def test_connection_cache(self):
        patterns = {"suspicious_ports": [4444]}
        nm = NetworkMonitor(patterns, cache_ttl=1.0)

        Addr = SimpleNamespace
        conn = SimpleNamespace(raddr=Addr(ip="8.8.8.8", port=4444), pid=1)

        calls = []

        def fake_net_connections(kind="inet"):
            calls.append(1)
            return [conn]

        from utils.psutil_compat import psutil
        orig = psutil.net_connections
        psutil.net_connections = fake_net_connections
        try:
            first = nm.check_now()
            second = nm.check_now()
            self.assertEqual(len(first), 1)
            self.assertEqual(len(second), 0)
            time.sleep(1.1)
            third = nm.check_now()
            self.assertEqual(len(third), 1)
        finally:
            psutil.net_connections = orig

if __name__ == "__main__":
    unittest.main()
