"""
Tests for Lock On monitoring system
"""
import unittest
import tempfile
import shutil
from pathlib import Path
import time

from src.core.monitor import FolderMonitor
from src.core.analyzer import PatternAnalyzer
from src.core.permissions import PermissionManager


class TestFolderMonitor(unittest.TestCase):
    """Test folder monitoring functionality"""

    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.monitor = FolderMonitor()
        self.monitor.set_target_folder(self.test_dir)

    def tearDown(self):
        """Clean up test environment"""
        self.monitor.stop()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_file_detection(self):
        """Test file creation detection"""
        detected_files = []

        def on_file_changed(action, filepath):
            if action == 'created':
                detected_files.append(filepath)

        self.monitor.on_file_changed = on_file_changed
        self.monitor.start()

        # Create test file
        test_file = Path(self.test_dir) / "test.txt"
        test_file.write_text("test content")

        # Wait for detection
        time.sleep(1)

        self.assertEqual(len(detected_files), 1)
        self.assertEqual(detected_files[0].name, "test.txt")

    def test_threat_detection(self):
        """Test threat detection"""
        threats_detected = []

        def on_threat(filepath, risk):
            threats_detected.append((filepath, risk))

        self.monitor.on_threat_detected = on_threat
        self.monitor.start()

        # Create suspicious file
        suspicious_file = Path(self.test_dir) / "malware.exe"
        suspicious_file.write_bytes(b"MZ\x90\x00\x03")  # PE header

        time.sleep(1)

        self.assertGreater(len(threats_detected), 0)


class TestPatternAnalyzer(unittest.TestCase):
    """Test pattern analysis"""

    def setUp(self):
        """Set up test environment"""
        self.analyzer = PatternAnalyzer()
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up"""
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_suspicious_extension(self):
        """Test suspicious file extension detection"""
        # Create test file with suspicious extension
        test_file = Path(self.test_dir) / "test.exe"
        test_file.write_text("test")

        result = self.analyzer.analyze_file(test_file)

        self.assertIn(result.level, ['high', 'medium'])

    def test_safe_file(self):
        """Test safe file analysis"""
        # Create safe file
        safe_file = Path(self.test_dir) / "document.txt"
        safe_file.write_text("Safe content")

        result = self.analyzer.analyze_file(safe_file)

        self.assertEqual(result.level, 'low')


class TestPermissions(unittest.TestCase):
    """Test permission management"""

    def setUp(self):
        """Set up test environment"""
        self.permissions = PermissionManager()

    def test_file_permissions(self):
        """Test file permission checking"""
        # Test blocked extension
        blocked_file = Path("test.exe")
        allowed = self.permissions.check_file_permission(blocked_file, 'create')
        self.assertFalse(allowed)

        # Test allowed file
        safe_file = Path("document.txt")
        allowed = self.permissions.check_file_permission(safe_file, 'create')
        self.assertTrue(allowed)

    def test_process_permissions(self):
        """Test process permission checking"""
        # Test whitelisted process
        allowed = self.permissions.check_process_permission("python.exe", 'execute')
        self.assertTrue(allowed)

        # Update blacklist
        self.permissions.update_blacklist(["malware.exe"], add=True)

        # Test blacklisted process
        allowed = self.permissions.check_process_permission("malware.exe", 'execute')
        self.assertFalse(allowed)


if __name__ == '__main__':
    unittest.main()
