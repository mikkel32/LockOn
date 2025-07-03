import os
from pathlib import Path
from security.yara_scanner import YaraScanner


def write_rules(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "rules.yar"
    path.write_text(text)
    return path


def test_literal_match(tmp_path):
    rules = write_rules(tmp_path, '''
rule Test {
    strings:
        $a = "foo"
    condition:
        $a
}''')
    scanner = YaraScanner(rules)
    assert scanner.scan_bytes(b"foo") == ["Test"]
    meta = scanner.scan_bytes_meta(b"foo")
    assert meta == [("Test", {})]


def test_hex_and_meta(tmp_path):
    rules = write_rules(tmp_path,
        '''
rule Hex {
    meta:
        threat = "x"
    strings:
        $h = {90 90}
    condition:
        $h
}''')
    scanner = YaraScanner(rules)
    assert scanner.scan_bytes(b"\x90\x90") == ["Hex"]
    assert scanner.threat_map["hex"] == "x"


def test_any_all(tmp_path):
    rules = write_rules(tmp_path,
        '''
rule Multi {
    strings:
        $a = "a"
        $b = "b"
    condition:
        any of them
}
rule MultiAll {
    strings:
        $a = "a"
        $b = "b"
    condition:
        all of them
}
''')
    scanner = YaraScanner(rules)
    assert set(scanner.scan_bytes(b"ab")) == {"Multi", "MultiAll"}
    assert scanner.scan_bytes(b"a") == ["Multi"]


def test_at_zero(tmp_path):
    rules = write_rules(tmp_path,
        '''
rule Start {
    strings:
        $m = {4D 5A}
    condition:
        $m at 0
}''')
    scanner = YaraScanner(rules)
    assert scanner.scan_bytes(b"\x4d\x5a\x00") == ["Start"]
    assert scanner.scan_bytes(b"XX\x4d\x5a") == []
