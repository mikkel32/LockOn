import pytest
from core.intelligence import IntelligenceEngine


def test_analyze_env_vars():
    engine = IntelligenceEngine()
    env = {"LD_PRELOAD": "evil.so", "PATH": "/usr/bin"}
    res = engine.analyze_env_vars(env)
    assert res["risk_level"] in ["medium", "high", "critical"]
    assert "ld_preload" in res["matches"]
