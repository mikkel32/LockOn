import pytest
from core.intelligence import IntelligenceEngine


def test_analyze_env_vars():
    engine = IntelligenceEngine()
    env = {"LD_PRELOAD": "evil.so", "PATH": "/usr/bin"}
    res = engine.analyze_env_vars(env)
    assert res["risk_level"] in ["medium", "high", "critical"]
    assert "ld_preload" in res["matches"]


def test_extract_snippet_lines():
    engine = IntelligenceEngine()
    text = "one\ntwo dangerous command\nthree"
    res = engine._extract_snippet_lines(text, "dangerous", 1)
    assert res["line"] == 2
    assert "two" in res["text"]
