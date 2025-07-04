"""
Intelligence Engine - Advanced pattern analysis and threat detection
"""
import json
import re
import zipfile
import io
from pathlib import Path
from typing import Dict, List
from utils.paths import resource_path

try:
    from security.yara_scanner import YaraScanner  # type: ignore
except Exception:
    YaraScanner = None
from datetime import datetime
try:
    import numpy as np  # type: ignore
except ImportError:  # pragma: no cover - fallback if numpy is unavailable
    import math
    import random

    class _SimpleNumpy:
        @staticmethod
        def mean(values):
            return sum(values) / len(values) if values else 0.0

        @staticmethod
        def array(seq):
            return list(seq)

        @staticmethod
        def dot(a, b):
            return sum(x * y for x, y in zip(a, b))

        @staticmethod
        def exp(x):
            return math.exp(x)

        class random:
            @staticmethod
            def rand(n):
                return [random.random() for _ in range(n)]

    np = _SimpleNumpy()
from collections import defaultdict


class IntelligenceEngine:
    """Advanced intelligence and pattern matching engine"""

    def __init__(self, yara_scanner: "YaraScanner | None" = None):
        self.patterns = self._load_patterns()
        self.rules = self._load_rules()
        self.behaviors = self._load_behaviors()
        self.responses = self._load_responses()

        # Learning data
        self.behavior_history = defaultdict(list)
        self.threat_scores = {}
        self.ml_model = self._initialize_ml_model()

        # Optional YARA scanner for signature detection
        if yara_scanner:
            self.yara_scanner = yara_scanner
        else:
            rules_path = resource_path("Intelligence", "yara_rules.yar")
            self.yara_scanner = YaraScanner(rules_path) if YaraScanner else None

    def _load_patterns(self) -> Dict:
        """Load pattern definitions"""
        pattern_file = resource_path("Intelligence", "patterns.json")
        if pattern_file.exists():
            try:
                data = json.load(open(pattern_file, 'r'))
                if 'file_patterns' in data or 'suspicious_extensions' in data:
                    return data
            except Exception:
                pass
        return self._get_default_patterns()

    def _load_rules(self) -> Dict:
        """Load security rules"""
        rules_file = resource_path("Intelligence", "rules.json")
        if rules_file.exists():
            with open(rules_file, 'r') as f:
                return json.load(f)
        return self._get_default_rules()

    def _load_behaviors(self) -> Dict:
        """Load behavior patterns"""
        behaviors_file = resource_path("Intelligence", "behaviors.json")
        if behaviors_file.exists():
            with open(behaviors_file, 'r') as f:
                return json.load(f)
        return self._get_default_behaviors()

    def _load_responses(self) -> Dict:
        """Load response strategies"""
        responses_file = resource_path("Intelligence", "responses.json")
        if responses_file.exists():
            with open(responses_file, 'r') as f:
                return json.load(f)
        return self._get_default_responses()

    def _get_default_patterns(self) -> Dict:
        """Get default patterns if file not found"""
        return {
            "file_patterns": {
                "suspicious_extensions": {
                    "high_risk": [".exe", ".dll", ".bat", ".cmd"],
                    "medium_risk": [".ps1", ".vbs", ".js"]
                }
            }
        }

    def _get_default_rules(self) -> Dict:
        """Get default rules if file not found"""
        return {
            "security_rules": {
                "file_operations": {
                    "create": {"blocked_extensions": [".exe", ".dll"]}
                }
            }
        }

    def _get_default_behaviors(self) -> Dict:
        """Get default behaviors if file not found"""
        return {
            "behavior_analysis": {
                "suspicious_behaviors": {
                    "file_scanning": {"threshold": "100+ files/min"}
                }
            }
        }

    def _get_default_responses(self) -> Dict:
        """Get default responses if file not found"""
        return {
            "response_strategies": {
                "immediate_responses": {
                    "block": {"severity": ["critical", "high"]}
                }
            }
        }

    def _initialize_ml_model(self):
        """Initialize machine learning model for anomaly detection"""
        # Simplified ML model initialization
        # In production, this would load a trained model
        return {
            'threshold': 0.8,
            'features': ['file_access_rate', 'process_count', 'cpu_usage'],
            'weights': np.random.rand(3)
        }

    def analyze_file_pattern(self, filepath: Path) -> Dict[str, any]:
        """Analyze file against known patterns"""
        result = {
            'risk_level': 'low',
            'matches': [],
            'confidence': 0.0,
            'recommendations': []
        }

        # Check extension
        ext = filepath.suffix.lower()
        patterns = self.patterns.get('file_patterns', self.patterns)
        susp_ext = patterns.get('suspicious_extensions', {})
        if isinstance(susp_ext, list):
            high_risk_exts = susp_ext
            medium_risk_exts: list[str] = []
        else:
            high_risk_exts = susp_ext.get('high_risk', [])
            medium_risk_exts = susp_ext.get('medium_risk', [])

        if ext in high_risk_exts:
            result['risk_level'] = 'high'
            result['matches'].append(f"High-risk extension: {ext}")
            result['confidence'] = 0.9

        elif ext in medium_risk_exts:
            result['risk_level'] = 'medium'
            result['matches'].append(f"Medium-risk extension: {ext}")
            result['confidence'] = 0.6

        # Check filename patterns
        filename = filepath.name
        for pattern in patterns.get('filename_patterns', {}).get('suspicious_names', []):
            if re.match(pattern, filename):
                result['risk_level'] = 'high'
                result['matches'].append(f"Suspicious filename pattern: {pattern}")
                result['confidence'] = max(result['confidence'], 0.8)

        # Content analysis (if file is readable)
        if filepath.exists() and filepath.stat().st_size < 10 * 1024 * 1024:  # 10MB limit
            content_risk = self._analyze_file_content(filepath)
            if content_risk['risk'] > 0.5:
                result['risk_level'] = 'high' if content_risk['risk'] > 0.8 else 'medium'
                result['matches'].extend(content_risk['matches'])
                result['confidence'] = max(result['confidence'], content_risk['risk'])

        return result

    def _analyze_file_content(self, filepath: Path) -> Dict[str, any]:
        """Analyze file content for malicious patterns"""
        result = {'risk': 0.0, 'matches': []}

        try:
            with open(filepath, 'rb') as f:
                # Read first 1MB
                content = f.read(1024 * 1024)

            patterns_root = self.patterns.get('content_patterns', {})
            file_patterns = self.patterns.get('file_patterns', {})
            patterns = file_patterns.get('content_patterns', patterns_root)

            result = self._analyze_raw_content(content, patterns)

            if zipfile.is_zipfile(filepath):
                zip_result = self._scan_zip_contents(filepath, patterns)
                if zip_result['risk'] > result['risk']:
                    result = zip_result
                else:
                    result['matches'].extend(zip_result['matches'])

        except Exception:
            # Can't read file
            pass

        return result

    def _analyze_raw_content(self, content: bytes, patterns: Dict) -> Dict[str, any]:
        """Analyze raw *content* bytes using detection patterns."""
        result = {'risk': 0.0, 'matches': []}

        content_hex = content.hex()
        if self.yara_scanner:
            matches = self.yara_scanner.scan_bytes(content)
            meta = self.yara_scanner.scan_bytes_meta(content)
            if matches:
                result['risk'] = max(result['risk'], 0.9)
                result['matches'].extend([f"yara:{m}" for m in matches])
                if meta:
                    result.setdefault('yara_meta', []).extend(meta)
        for sig in patterns.get('malicious_signatures', []):
            if sig.lower() in content_hex.lower():
                result['risk'] = 0.9
                result['matches'].append(f"Malicious signature found: {sig[:10]}...")

        try:
            content_str = content.decode('utf-8', errors='ignore')
            for string in patterns.get('suspicious_strings', []):
                if string.lower() in content_str.lower():
                    result['risk'] = max(result['risk'], 0.6)
                    result['matches'].append(f"Suspicious string: {string}")

            revshell_patterns = [
                r"bash\s+-i\s+>&\s*/dev/tcp/",
                r"nc\s+-e\s+/bin/sh",
            ]
            for pat in revshell_patterns:
                if re.search(pat, content_str, re.IGNORECASE):
                    result['risk'] = max(result['risk'], 0.9)
                    result['matches'].append('Reverse shell command')
                    break

            ip_hits = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}\b", content_str)
            if ip_hits:
                result['risk'] = max(result['risk'], 0.6)
                result['matches'].append('Suspicious IP address')

            import base64
            encoded_strings = re.findall(r'[A-Za-z0-9+/=]{20,}', content_str)
            for enc in encoded_strings:
                try:
                    decoded_bytes = base64.b64decode(enc)
                    decoded = decoded_bytes.decode('utf-8', 'ignore').lower()
                    if any(token in decoded for token in ['powershell', 'cmd.exe']):
                        result['risk'] = max(result['risk'], 0.7)
                        result['matches'].append('Suspicious base64 command')
                        break
                    if 'eicar-standard-antivirus-test-file' in decoded:
                        result['risk'] = max(result['risk'], 0.9)
                        result['matches'].append('EICAR signature (base64)')
                        break
                    if self.yara_scanner:
                        ym = self.yara_scanner.scan_bytes(decoded_bytes)
                        if ym:
                            result['risk'] = max(result['risk'], 0.9)
                            result['matches'].extend([f'yara:{m}' for m in ym])
                            break
                except Exception:
                    continue
        except Exception:
            pass

        return result

    def _scan_zip_contents(self, filepath: Path | io.BytesIO, patterns: Dict, depth: int = 0) -> Dict[str, any]:
        """Scan files inside zip archive for malicious patterns recursively."""
        result = {'risk': 0.0, 'matches': []}
        if depth > 2:
            return result
        try:
            with zipfile.ZipFile(filepath, 'r') as zf:
                for idx, name in enumerate(zf.namelist()):
                    if idx >= 10:
                        break
                    try:
                        data = zf.read(name)
                    except Exception:
                        continue
                    sub = self._analyze_raw_content(data, patterns)
                    if self.yara_scanner:
                        yara_matches = self.yara_scanner.scan_bytes(data)
                        meta = self.yara_scanner.scan_bytes_meta(data)
                        if yara_matches:
                            sub['risk'] = max(sub['risk'], 0.9)
                            sub['matches'].extend([f"yara:{m}" for m in yara_matches])
                            if meta:
                                sub.setdefault('yara_meta', []).extend(meta)
                    if zipfile.is_zipfile(io.BytesIO(data)):
                        nested = self._scan_zip_contents(io.BytesIO(data), patterns, depth + 1)
                        if nested['risk'] > sub['risk']:
                            sub = nested
                        else:
                            sub['matches'].extend(nested['matches'])
                            if 'yara_meta' in nested:
                                sub.setdefault('yara_meta', []).extend(nested['yara_meta'])
                    if sub['risk'] > result['risk']:
                        result = sub
                        result['matches'] = [f"{name}: {m}" for m in sub['matches']]
                        if 'yara_meta' in sub:
                            result['yara_meta'] = sub['yara_meta']
                    elif sub['risk'] > 0:
                        result['matches'].extend([f"{name}: {m}" for m in sub['matches']])
                        if 'yara_meta' in sub:
                            result.setdefault('yara_meta', []).extend(sub['yara_meta'])
        except Exception:
            pass
        return result

    def analyze_behavior(self, event_type: str, details: Dict) -> Dict[str, any]:
        """Analyze behavior patterns"""
        # Track behavior
        self.behavior_history[event_type].append({
            'timestamp': datetime.now(),
            'details': details
        })

        # Analyze patterns
        analysis = {
            'anomaly_score': 0.0,
            'threat_type': None,
            'confidence': 0.0,
            'action_required': False
        }

        # Check for rapid file changes
        if event_type == 'file_modified':
            recent_mods = [e for e in self.behavior_history['file_modified']
                          if (datetime.now() - e['timestamp']).seconds < 60]

            if len(recent_mods) > 50:
                analysis['anomaly_score'] = 0.9
                analysis['threat_type'] = 'ransomware'
                analysis['confidence'] = 0.85
                analysis['action_required'] = True

        # Check for mass deletion
        elif event_type == 'file_deleted':
            recent_dels = [e for e in self.behavior_history['file_deleted']
                          if (datetime.now() - e['timestamp']).seconds < 300]

            if len(recent_dels) > 20:
                analysis['anomaly_score'] = 0.8
                analysis['threat_type'] = 'wiper'
                analysis['confidence'] = 0.75
                analysis['action_required'] = True

        return analysis

    def get_response_strategy(self, threat_level: str, threat_type: str) -> Dict:
        """Get appropriate response strategy"""
        strategies = self.responses.get('response_strategies', {})

        # Immediate responses
        if threat_level in ['critical', 'high']:
            if threat_type == 'ransomware':
                return strategies.get('defensive_responses', {}).get('lockdown', {})
            elif threat_type == 'encryption':
                return strategies.get('immediate_responses', {}).get('terminate', {})
            else:
                return strategies.get('immediate_responses', {}).get('block', {})

        # Medium threats
        elif threat_level == 'medium':
            return strategies.get('immediate_responses', {}).get('quarantine', {})

        # Low threats
        else:
            return strategies.get('immediate_responses', {}).get('sandbox', {})

    def calculate_threat_score(self, filepath: Path, behaviors: List[Dict]) -> float:
        """Calculate overall threat score using ML"""
        features = []

        # Extract features
        file_access_rate = len([b for b in behaviors if b['type'] == 'file_access']) / 60
        process_count = len(set(b.get('pid', 0) for b in behaviors))
        cpu_usage = np.mean([b.get('cpu', 0) for b in behaviors])

        features = np.array([file_access_rate, process_count, cpu_usage])

        # Simple anomaly detection
        score = np.dot(features, self.ml_model['weights'])
        normalized_score = 1 / (1 + np.exp(-score))  # Sigmoid

        return normalized_score

    def analyze_network_connection(self, ip: str, port: int) -> Dict[str, any]:
        """Analyze network connection attributes for potential risk."""
        result = {
            'risk_level': 'low',
            'matches': [],
            'confidence': 0.0,
            'type': 'network_activity',
        }
        ports = self.patterns.get('suspicious_ports', [])
        ips = self.patterns.get('suspicious_ips', [])
        if port in ports:
            result['risk_level'] = 'high'
            result['confidence'] = 0.8
            result['matches'].append(f'suspicious port {port}')
            result['type'] = 'c2_communication'
        if any(str(ip).startswith(prefix) for prefix in ips):
            if result['risk_level'] != 'high':
                result['risk_level'] = 'medium'
                result['confidence'] = max(result['confidence'], 0.6)
            result['matches'].append(f'suspicious ip {ip}')
            result['type'] = 'c2_communication'
        return result

    def analyze_env_vars(self, env: Dict[str, str]) -> Dict[str, any]:
        """Analyze process environment variables for suspicious entries."""
        result = {
            'risk_level': 'low',
            'confidence': 0.0,
            'matches': [],
            'type': 'environment',
        }

        patterns = [p.lower() for p in self.patterns.get('suspicious_env_vars', [])]
        if not patterns:
            return result
        for k, v in env.items():
            combined = f"{k}={v}".lower()
            for pat in patterns:
                if pat in combined:
                    result['matches'].append(pat)
                    result['risk_level'] = 'medium'
                    result['confidence'] = max(result['confidence'], 0.6)
        if result['matches']:
            if len(result['matches']) > 2:
                result['risk_level'] = 'high'
                result['confidence'] = max(result['confidence'], 0.8)
        return result

    def learn_from_event(self, event: Dict, was_threat: bool):
        """Update ML model based on event feedback"""
        # In a real implementation, this would update the model
        # based on whether the event was actually a threat
        pass

    def get_recommendations(self, threat_analysis: Dict) -> List[str]:
        """Get security recommendations"""
        recommendations = []

        if threat_analysis.get('risk_level') == 'high':
            recommendations.append("Immediately quarantine the file")
            recommendations.append("Scan system for similar threats")
            recommendations.append("Enable maximum protection mode")

        elif threat_analysis.get('risk_level') == 'medium':
            recommendations.append("Monitor file activity closely")
            recommendations.append("Restrict file permissions")
            recommendations.append("Create backup of important files")

        else:
            recommendations.append("Continue normal monitoring")
            recommendations.append("Update threat definitions")

        return recommendations
