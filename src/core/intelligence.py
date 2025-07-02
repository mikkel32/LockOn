"""
Intelligence Engine - Advanced pattern analysis and threat detection
"""
import json
import re
import hashlib
from pathlib import Path
from typing import Dict, List, Tuple, Optional
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

    def __init__(self):
        self.patterns = self._load_patterns()
        self.rules = self._load_rules()
        self.behaviors = self._load_behaviors()
        self.responses = self._load_responses()

        # Learning data
        self.behavior_history = defaultdict(list)
        self.threat_scores = {}
        self.ml_model = self._initialize_ml_model()

    def _load_patterns(self) -> Dict:
        """Load pattern definitions"""
        pattern_file = Path("Intelligence/patterns.json")
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
        rules_file = Path("Intelligence/rules.json")
        if rules_file.exists():
            with open(rules_file, 'r') as f:
                return json.load(f)
        return self._get_default_rules()

    def _load_behaviors(self) -> Dict:
        """Load behavior patterns"""
        behaviors_file = Path("Intelligence/behaviors.json")
        if behaviors_file.exists():
            with open(behaviors_file, 'r') as f:
                return json.load(f)
        return self._get_default_behaviors()

    def _load_responses(self) -> Dict:
        """Load response strategies"""
        responses_file = Path("Intelligence/responses.json")
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

            # Check for malicious signatures
            content_hex = content.hex()
            patterns = self.patterns.get('file_patterns', {}).get('content_patterns', {})

            for sig in patterns.get('malicious_signatures', []):
                if sig.lower() in content_hex.lower():
                    result['risk'] = 0.9
                    result['matches'].append(f"Malicious signature found: {sig[:10]}...")

            # Check for suspicious strings
            try:
                content_str = content.decode('utf-8', errors='ignore')
                for string in patterns.get('suspicious_strings', []):
                    if string.lower() in content_str.lower():
                        result['risk'] = max(result['risk'], 0.6)
                        result['matches'].append(f"Suspicious string: {string}")
            except:
                pass

        except Exception as e:
            # Can't read file
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
