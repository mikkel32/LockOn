import types
import sys
import subprocess
from scripts import manage_vm

class FakeProcError(Exception):
    pass

def _fake_run(cmd, check=True, env=None):
    _fake_run.calls.append((cmd, env))
    if cmd and any("pip" in part for part in cmd):
        sys.modules["debugpy"] = types.ModuleType("debugpy")


def _fake_spawn(cmd, env=None):
    _fake_spawn.calls.append((cmd, env))
    class P:
        pid = 1234
    return P()


def test_start_prefers_vagrant(monkeypatch):
    _fake_run.calls = []
    monkeypatch.setattr(manage_vm, "_spawn", _fake_spawn)
    monkeypatch.setattr(manage_vm, "_run", _fake_run)
    monkeypatch.setattr(manage_vm, "which", lambda name: "/bin/vagrant" if name == "vagrant" else None)
    manage_vm.main(["start", "--port", "6000"])
    assert any(call[0] == ["vagrant", "up"] and call[1]["LOCKON_DEBUG_PORT"] == "6000" for call in _fake_run.calls)


def test_start_falls_back_to_docker(monkeypatch):
    _fake_run.calls = []
    monkeypatch.setattr(manage_vm, "_spawn", _fake_spawn)
    monkeypatch.setattr(manage_vm, "_run", _fake_run)
    def fake_which(name):
        if name == "vagrant":
            return None
        return "/bin/docker" if name in {"docker", "docker-compose"} else None
    monkeypatch.setattr(manage_vm, "which", fake_which)
    manage_vm.main(["start", "--port", "6000"])
    assert any(call[0] == ["docker-compose", "up", "--build", "-d"] and call[1]["LOCKON_DEBUG_PORT"] == "6000" for call in _fake_run.calls)


def test_local_backend_when_no_env(monkeypatch, tmp_path, capsys):
    _fake_run.calls = []
    _fake_spawn.calls = []
    monkeypatch.setattr(manage_vm, "_run", _fake_run)
    monkeypatch.setattr(manage_vm, "_spawn", _fake_spawn)
    monkeypatch.setattr(manage_vm, "which", lambda name: None)
    monkeypatch.setenv("LOCKON_LOCAL_PID", str(tmp_path / "pid"))
    sys.modules.pop("debugpy", None)
    manage_vm.main(["start", "--port", "6000"])
    out = capsys.readouterr().err
    assert "debugpy not found" in out
    assert any("pip" in part for r in _fake_run.calls for part in r[0])
    assert _fake_spawn.calls


def test_doctor_calls_backend(monkeypatch):
    _fake_run.calls = []
    monkeypatch.setattr(manage_vm, "_run", _fake_run)
    monkeypatch.setattr(manage_vm, "which", lambda name: "/bin/vagrant" if name == "vagrant" else None)
    manage_vm.main(["doctor"])
    assert any(
        call[0] == ["vagrant", "ssh", "-c", "python3 -c 'import debugpy'"] for call in _fake_run.calls
    )


def test_doctor_local_backend(monkeypatch, capsys):
    monkeypatch.setattr(manage_vm, "which", lambda name: None)
    monkeypatch.setattr(manage_vm, "_run", _fake_run)
    monkeypatch.setattr(manage_vm, "_spawn", _fake_spawn)
    _fake_run.calls = []
    _fake_spawn.calls = []
    sys.modules.pop("debugpy", None)
    manage_vm.main(["doctor"])
    out = capsys.readouterr().err
    assert "debugpy not found" in out
    assert any("pip" in part for call in _fake_run.calls for part in call[0])


def test_doctor_docker_backend(monkeypatch):
    _fake_run.calls = []
    monkeypatch.setattr(manage_vm, "_run", _fake_run)

    def fake_which(name):
        if name == "vagrant":
            return None
        return "/bin/docker" if name in {"docker", "docker-compose"} else None

    monkeypatch.setattr(manage_vm, "which", fake_which)
    manage_vm.main(["doctor"])
    assert any(
        call[0][:3] == ["docker-compose", "exec", "lockon"]
        for call in _fake_run.calls
    )


def test_local_start_without_debugpy(monkeypatch, capsys):
    monkeypatch.setattr(manage_vm, "which", lambda name: None)
    monkeypatch.setattr(manage_vm, "_run", _fake_run)
    monkeypatch.setattr(manage_vm, "_spawn", _fake_spawn)
    _fake_run.calls = []
    _fake_spawn.calls = []
    sys.modules.pop("debugpy", None)
    manage_vm.main(["start"])
    out = capsys.readouterr().err
    assert "debugpy not found" in out
    assert any("pip" in part for r in _fake_run.calls for part in r[0])
    assert _fake_spawn.calls


def test_local_halt_and_status(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(manage_vm, "which", lambda name: None)
    monkeypatch.setattr(manage_vm, "_run", _fake_run)
    monkeypatch.setattr(manage_vm, "_spawn", _fake_spawn)
    monkeypatch.setenv("LOCKON_LOCAL_PID", str(tmp_path / "pid"))
    sys.modules["debugpy"] = types.ModuleType("debugpy")

    manage_vm.main(["start"])
    assert (tmp_path / "pid").exists()

    manage_vm.main(["status"])
    out = capsys.readouterr().out
    assert "running" in out

    manage_vm.main(["halt"])
    assert not (tmp_path / "pid").exists()
