from utils.helpers import parse_threat_details
from utils.threat import ThreatSummary


def test_parse_threat_details_basic():
    details = {"snippets": [{"text": "bad code", "line": 1}], "matches": ["yara:evil"]}
    snip, match, line = parse_threat_details(details)
    assert snip == "bad code"
    assert match == "yara:evil"
    assert line == 1


def test_parse_threat_details_none():
    snip, match, line = parse_threat_details(None)
    assert snip is None and match is None and line is None


def test_parse_threat_details_truncate():
    text = "x" * 200
    snip, match, line = parse_threat_details({"snippets": [{"text": text, "line": 1}]})
    assert snip.endswith("...")
    assert len(snip) <= 120



def test_threat_summary_from_detection():
    class Risk:
        level = "high"
        type = "malware"
        details = {"snippets": [{"text": "bad", "line": 2}], "matches": ["yara:evil"]}

    ts = ThreatSummary.from_detection("f.exe", Risk)
    assert ts.snippet == "bad"
    assert ts.match == "yara:evil"
    assert ts.line == 2
    assert ts.level == "high"
    assert ts.type == "malware"


def test_threat_summary_format_color(capsys):
    ts = ThreatSummary(
        path="f.exe",
        level="critical",
        type="malware",
        match="rule",
        snippet="bad",
        line=3,
        details={},
    )
    print(ts.format(color=True))
    out = capsys.readouterr().out
    assert "f.exe" in out and "bad" in out and "rule" in out
    assert "\x1b[" in out


def test_threat_summary_dict_roundtrip():
    ts = ThreatSummary(
        path="p",
        level="high",
        type="t",
        match="evil",
        snippet="good evil bad",
        line=4,
        details={"matches": ["evil"], "snippets": [{"text": "good evil bad", "line": 4}]},
    )
    data = ts.to_dict()
    ts2 = ThreatSummary.from_dict(data)
    assert ts2 == ts


def test_highlight_in_format(capsys):
    ts = ThreatSummary(
        path="x",
        level="low",
        type="t",
        match="bad",
        snippet="good bad code",
        line=1,
        details={},
    )
    print(ts.format(color=True))
    out = capsys.readouterr().out
    assert "\x1b[31mbad\x1b[0m" in out


def test_threat_summary_format_plain():
    ts = ThreatSummary(path="a", level="low", type=None, match=None, snippet="snip", line=None, details={})
    assert ts.format() == "Threat detected: a - Level: low Snippet: snip"

