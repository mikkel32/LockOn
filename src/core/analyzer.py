"""
Pattern Analyzer - Analyze files and behaviors for threats
"""

try:
    import magic  # type: ignore
except ImportError:  # pragma: no cover - fallback when python-magic is missing
    magic = None
    import mimetypes
import hashlib
import zipfile
from pathlib import Path
from typing import Dict
from datetime import datetime

from core.intelligence import IntelligenceEngine
from utils.psutil_compat import psutil
from utils.paths import resource_path
try:
    import pefile  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    pefile = None

try:
    from security.yara_scanner import YaraScanner  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    YaraScanner = None
from security.scanner import Scanner


class ThreatAnalysis:
    """Threat analysis result"""

    def __init__(self, level: str, type: str, confidence: float, details: Dict) -> None:
        self.level = level  # low, medium, high, critical
        self.type = type  # malware, ransomware, trojan, etc
        self.confidence = confidence
        self.details = details
        self.timestamp = datetime.now()


class PatternAnalyzer:
    """Advanced pattern analysis engine"""

    def __init__(self):
        rules = resource_path("Intelligence", "yara_rules.yar")
        self.yara_scanner = YaraScanner(rules) if YaraScanner else None
        self.intelligence = IntelligenceEngine(self.yara_scanner)
        self.scanner = Scanner(self.yara_scanner)
        if magic:
            self.file_magic = magic.Magic()
        else:
            self.file_magic = None
        self.known_hashes = self._load_known_hashes()

    def _load_known_hashes(self) -> Dict[str, str]:
        """Load database of known malicious file hashes"""
        # In production, this would load from a threat database
        return {
            # Example malicious hash of an empty file
            "d41d8cd98f00b204e9800998ecf8427e": "EmptyFile.Suspicious",
        }

    def analyze_file(self, filepath: Path) -> ThreatAnalysis:
        """Analyze *filepath* using loaded patterns and heuristics."""

        # Check known malicious hashes first and gather YARA matches
        scan_result = self.scanner.scan(str(filepath))
        file_hash = scan_result.get("hash", "")
        yara_matches = scan_result.get("yara", [])
        yara_meta = scan_result.get("yara_meta", [])
        if file_hash in self.known_hashes:
            return ThreatAnalysis(
                "critical",
                "known_malware",
                1.0,
                {"hash": file_hash, "signature": self.known_hashes[file_hash]},
            )

        analysis = self.intelligence.analyze_file_pattern(filepath)
        level = analysis["risk_level"]
        confidence = analysis["confidence"]

        # Adjust risk based on MIME mismatch heuristics
        mime_score = self._check_mime_mismatch(filepath)
        if mime_score:
            if mime_score > 0.7:
                level = "high"
            elif level == "low":
                level = "medium"
            confidence = max(confidence, mime_score)
            analysis.setdefault("matches", []).append("mime_mismatch")

        # YARA scanning for additional threat detection
        if yara_matches:
            analysis.setdefault("matches", []).extend(
                [f"yara:{m}" for m in yara_matches]
            )
            if yara_meta:
                analysis["yara_meta"] = yara_meta
            level = "high"
            confidence = max(confidence, 0.9)

            if zipfile.is_zipfile(filepath):
                with zipfile.ZipFile(filepath, "r") as zf:
                    for idx, name in enumerate(zf.namelist()):
                        if idx >= 10:
                            break
                        try:
                            data = zf.read(name)
                        except Exception:
                            continue
                        sub_matches = self.yara_scanner.scan_bytes(data)
                        sub_meta = self.yara_scanner.scan_bytes_meta(data)
                        if sub_matches:
                            analysis.setdefault("matches", []).extend(
                                [f"yara:{m}" for m in sub_matches]
                            )
                            if sub_meta:
                                metas = analysis.setdefault("yara_meta", [])
                                metas.extend(sub_meta)
                            level = "high"
                            confidence = max(confidence, 0.9)

        if filepath.suffix.lower() in [".exe", ".dll"] and not self._is_signed(filepath):
            analysis.setdefault("matches", []).append("unsigned_executable")
            if level == "low":
                level = "medium"
            confidence = max(confidence, 0.6)

        threat_type = self._determine_threat_type(filepath, analysis)
        details = {
            "matches": analysis.get("matches", []),
            "confidence": confidence,
        }
        if analysis.get("snippets"):
            details["snippets"] = analysis["snippets"]
        if "yara_meta" in analysis:
            details["yara_meta"] = analysis["yara_meta"]

        return ThreatAnalysis(level, threat_type, confidence, details)

    def _calculate_file_hash(self, filepath: Path) -> str:
        """Calculate MD5 hash of file"""
        hash_md5 = hashlib.md5()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception:
            return ""

    def analyze_connection(self, ip: str, port: int) -> ThreatAnalysis:
        """Analyze a network connection represented by *ip* and *port*."""
        res = self.intelligence.analyze_network_connection(ip, port)
        details = {"ip": ip, "port": port, "matches": res.get("matches", [])}
        return ThreatAnalysis(
            res.get("risk_level", "low"),
            res.get("type", "network_activity"),
            res.get("confidence", 0.0),
            details,
        )

    def _is_signed(self, filepath: Path) -> bool:
        """Return True if PE file has a digital signature."""
        if pefile is None:
            return False
        try:
            pe = pefile.PE(str(filepath), fast_load=True)
            return bool(
                hasattr(pe, "DIRECTORY_ENTRY_SECURITY") and pe.DIRECTORY_ENTRY_SECURITY
            )
        except Exception:
            return False

    def _check_mime_mismatch(self, filepath: Path) -> float:
        """Check if file type matches extension"""
        try:
            mime_type = self._get_mime_type(filepath)
            extension = filepath.suffix.lower()

            # Define expected MIME types for extensions
            expected_types = {
                ".exe": ["application/x-executable", "application/x-msdos-program"],
                ".jpg": ["image/jpeg"],
                ".png": ["image/png"],
                ".pdf": ["application/pdf"],
                ".doc": ["application/msword"],
                ".txt": ["text/plain"],
            }

            if extension in expected_types:
                expected = expected_types[extension]
                if not any(exp in mime_type for exp in expected):
                    # Mismatch detected - suspicious
                    return 0.8

            # Check for executable content in non-exe files
            if extension not in [".exe", ".dll", ".com"] and "executable" in mime_type:
                return 0.9

        except Exception:
            pass

        return 0.0

    def _get_mime_type(self, filepath: Path) -> str:
        """Get MIME type of file"""
        if self.file_magic:
            try:
                return self.file_magic.from_file(str(filepath))
            except Exception:
                return "unknown"
        else:
            mime_type, _ = mimetypes.guess_type(str(filepath))
            return mime_type or "unknown"

    def _risk_to_score(self, risk_level: str) -> float:
        """Convert risk level to numeric score"""
        scores = {"critical": 0.9, "high": 0.7, "medium": 0.5, "low": 0.2}
        return scores.get(risk_level, 0.0)

    def _determine_threat_type(self, filepath: Path, analysis: Dict) -> str:
        """Determine specific threat type"""
        # Check for YARA matches or decoded commands
        yara_map = {
            "yara:suspiciousmacro": "macro",
            "yara:zip_vba_project": "macro",
            "yara:reverseshell_bash": "reverse_shell",
            "yara:netcat_reverseshell": "reverse_shell",
            "yara:mimikatz_detected": "credential_theft",
            "yara:regsvr32_command": "script_malware",
            "yara:downloader_powershell": "malware_downloader",
            "yara:certutil_download": "malware_downloader",
            "yara:rundll32_command": "script_malware",
            "yara:suspicious_ip_connection": "c2_communication",
            "yara:eicar_test_file": "test_virus",
            "yara:hta_scriptlet": "script_malware",
            "yara:meterpreter_string": "malware",
            "yara:cobaltstrike_beacon": "malware",
            "yara:invoke_shellcode": "malware",
            "yara:powerview_module": "reconnaissance",
            "yara:dotnet_base64decode": "malware",
            "yara:invoke_obfuscation": "obfuscation",
            "yara:empire_ps": "malware",
            "yara:psexec_command": "lateral_movement",
            "yara:msbuild_shell": "malware_loader",
            "yara:installutil_command": "persistence",
            "yara:shellcode_loader": "malware_loader",
            "yara:njrat_string": "rat",
            "yara:darkcomet_string": "rat",
            "yara:agenttesla_string": "credential_theft",
            "yara:asyncrat_string": "rat",
            "yara:formbook_string": "stealer",
            "yara:upx_packed": "packed_executable",
            "yara:process_hollowing": "malware_loader",
            "yara:netsh_tunnel": "c2_communication",
            "yara:webhook_url": "data_exfiltration",
            "yara:autoit_compiled": "malware",
            "yara:keylogger_api": "keylogger",
            "yara:discord_tokenstealer": "credential_theft",
        }
        meta_list = analysis.get("yara_meta", [])
        for rule, meta in meta_list:
            threat = meta.get("threat") or meta.get("threat_type")
            if threat:
                return str(threat).lower()

        if self.yara_scanner:
            for m in analysis.get("matches", []):
                if not str(m).lower().startswith("yara:"):
                    continue
                rule = str(m)[5:].lower()
                mapped = self.yara_scanner.threat_map.get(rule)
                if mapped:
                    return mapped
        for m in analysis.get("matches", []):
            m_str = str(m).lower()
            if m_str.startswith("yara:"):
                return yara_map.get(m_str, "malware")
            if "base64 command" in m_str:
                return "malware"
            if "setwindowshookex" in m_str or "getasynckeystate" in m_str:
                return "keylogger"
            if "vbaproject.bin" in m_str:
                return "macro"
            if "mimikatz" in m_str:
                return "credential_theft"
            if "meterpreter" in m_str:
                return "malware"
            if "netsh" in m_str:
                return "c2_communication"

        # Check for ransomware patterns
        if any("encrypt" in match.lower() for match in analysis.get("matches", [])):
            return "ransomware"

        # Check for trojan patterns
        if self._check_trojan_patterns(filepath):
            return "trojan"

        # Check extension
        ext = filepath.suffix.lower()
        if ext in [".exe", ".dll", ".bat", ".cmd"]:
            return "potentially_unwanted"

        return "suspicious_file"

    def _check_trojan_patterns(self, filepath: Path) -> bool:
        """Check for trojan-like behavior patterns"""
        # Check if file is trying to hide
        if filepath.name.startswith("."):
            return True

        # Check for double extensions
        if len(filepath.suffixes) > 1:
            return True

        return False

    def detect_encryption(self, filepath: Path, old_hash: str, new_hash: str) -> bool:
        """Detect if file was encrypted"""
        if old_hash == new_hash:
            return False

        try:
            # Check entropy increase
            with open(filepath, "rb") as f:
                data = f.read(1024)  # Check first 1KB

            # Calculate entropy
            entropy = self._calculate_entropy(data)

            # High entropy suggests encryption
            if entropy > 7.5:
                return True

            # Check for ransomware file markers
            ransom_extensions = [".locked", ".encrypted", ".crypto", ".enc"]
            if any(str(filepath).endswith(ext) for ext in ransom_extensions):
                return True

        except Exception:
            pass

        return False

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        import math

        if not data:
            return 0.0

        # Count byte frequencies
        frequencies = {}
        for byte in data:
            frequencies[byte] = frequencies.get(byte, 0) + 1

        # Calculate entropy
        entropy = 0.0
        data_len = len(data)

        for count in frequencies.values():
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)

        return entropy

    def is_suspicious_process(self, process: psutil.Process) -> bool:
        """Check if process is suspicious"""
        try:
            proc_info = process.info
            name = proc_info.get("name", "").lower()

            # Check against known bad process names
            bad_names = ["cryptor", "miner", "ransom", "trojan", "virus"]
            if any(bad in name for bad in bad_names):
                return True

            # Analyze command line for malicious patterns
            if hasattr(process, "cmdline"):
                try:
                    cmdline = " ".join(process.cmdline())
                except Exception:
                    cmdline = ""
                if cmdline:
                    patterns = self.intelligence.patterns.get("content_patterns", {})
                    res = self.intelligence._analyze_raw_content(
                        cmdline.encode(), patterns
                    )
                    if res["risk"] >= 0.6:
                        return True
                    if self.yara_scanner:
                        ym = self.yara_scanner.scan_bytes(cmdline.encode())
                        if ym:
                            return True

            # Scan the process executable itself
            try:
                exe_path = process.exe()
            except Exception:
                exe_path = ""
            if exe_path:
                try:
                    risk = self.analyze_file(Path(exe_path))
                    if risk.level in ["high", "critical"]:
                        return True
                except Exception:
                    pass

            # Check network connections against suspicious ports/IPs
            try:
                if hasattr(process, "net_connections"):
                    conns = process.net_connections(kind="inet")
                else:
                    conns = process.connections(kind="inet")
                ports = set(self.intelligence.patterns.get("suspicious_ports", []))
                ip_prefixes = self.intelligence.patterns.get("suspicious_ips", [])
                for c in conns:
                    if not c.raddr:
                        continue
                    if c.raddr.port in ports:
                        return True
                    if any(str(c.raddr.ip).startswith(p) for p in ip_prefixes):
                        return True
            except Exception:
                pass

            # Check environment variables for suspicious indicators
            try:
                env = process.environ()
                res = self.intelligence.analyze_env_vars(env)
                if res["risk_level"] in ["medium", "high", "critical"]:
                    return True
            except Exception:
                pass

            # Check resource usage
            if proc_info.get("cpu_percent", 0) > 80:
                # High CPU usage for unknown process
                if name not in ["chrome.exe", "firefox.exe", "code.exe"]:
                    return True

            # Check for hidden processes
            if name.startswith(".") or name == "":
                return True

            # Check process tree
            if self._check_suspicious_parent(process):
                return True

        except Exception:
            pass

        return False

    def _check_suspicious_parent(self, process: psutil.Process) -> bool:
        """Check if process has suspicious parent"""
        try:
            parent = process.parent()
            if parent:
                parent_name = parent.name().lower()

                # Suspicious if spawned by cmd or powershell
                if parent_name in ["cmd.exe", "powershell.exe"]:
                    # Unless it's a known good process
                    if process.name().lower() not in ["python.exe", "node.exe"]:
                        return True

        except Exception:
            pass

        return False
