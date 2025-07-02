from pathlib import Path
from core.enforcer import ActionEnforcer


def test_quarantine_restore(tmp_path):
    enforcer = ActionEnforcer(tmp_path / "q")
    f = tmp_path / "mal.txt"
    f.write_text("data")
    enforcer.quarantine_file(f)
    qfile = enforcer.quarantine_manager.directory / f.name
    assert qfile.exists() and not f.exists()
    enforcer.restore_file(f)
    assert f.exists() and not qfile.exists()
