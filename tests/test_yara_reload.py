import time
from pathlib import Path
from security.yara_scanner import YaraScanner


def test_reload_rules(tmp_path):
    rules = tmp_path / "rules.yar"
    rules.write_text('rule Test1 { condition: true }')
    scanner = YaraScanner(rules)
    assert scanner.scan_bytes(b"data") == ["Test1"]
    # Modify rules
    time.sleep(1)
    rules.write_text('rule Test2 { condition: true }')
    assert scanner.scan_bytes(b"data") == ["Test2"]

