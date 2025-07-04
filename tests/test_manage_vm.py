import types
import sys
import subprocess
import builtins
import socket
import threading
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

def _fake_launch_vscode(workspace, port):
    _fake_launch_vscode.calls.append((workspace, port))

_fake_run.calls = []
_fake_spawn.calls = []
_fake_launch_vscode.calls = []


def test_start_prefers_vagrant(monkeypatch):
    _fake_run.calls = []
    monkeypatch.setattr(manage_vm, "_spawn", _fake_spawn)
    monkeypatch.setattr(manage_vm, "_run", _fake_run)
    monkeypatch.setattr(manage_vm, "_wait_for_port", lambda *a, **kw: True)
    monkeypatch.setattr(manage_vm, "which", lambda name: "/bin/vagrant" if name == "vagrant" else None)
    manage_vm.main(["start", "--port", "6000"])
    assert any(call[0] == ["vagrant", "up"] and call[1]["LOCKON_DEBUG_PORT"] == "6000" for call in _fake_run.calls)


def test_start_falls_back_to_docker(monkeypatch):
    _fake_run.calls = []
    monkeypatch.setattr(manage_vm, "_spawn", _fake_spawn)
    monkeypatch.setattr(manage_vm, "_run", _fake_run)
    monkeypatch.setattr(manage_vm, "_wait_for_port", lambda *a, **kw: True)
    def fake_which(name):
        if name == "vagrant":
            return None
        return "/bin/docker" if name in {"docker", "docker-compose"} else None
    monkeypatch.setattr(manage_vm, "which", fake_which)
    manage_vm.main(["start", "--port", "6000"])
    assert any(
        call[0][:2] == ["docker", "compose"] and call[0][2:] == ["up", "--build", "-d"] and call[1]["LOCKON_DEBUG_PORT"] == "6000"
        or call[0] == ["docker-compose", "up", "--build", "-d"] and call[1]["LOCKON_DEBUG_PORT"] == "6000"
        for call in _fake_run.calls
    )


def test_local_backend_when_no_env(monkeypatch, tmp_path, capsys):
    _fake_run.calls = []
    _fake_spawn.calls = []
    monkeypatch.setattr(manage_vm, "_run", _fake_run)
    monkeypatch.setattr(manage_vm, "_spawn", _fake_spawn)
    monkeypatch.setattr(manage_vm, "_wait_for_port", lambda *a, **kw: True)
    monkeypatch.setattr(manage_vm, "which", lambda name: None)
    monkeypatch.setenv("LOCKON_LOCAL_PID", str(tmp_path / "pid"))
    sys.modules.pop("debugpy", None)
    monkeypatch.setitem(sys.modules, "debugpy", None)
    real_import = builtins.__import__
    def fake_import(name, *a, **kw):
        if name == "debugpy" and "debugpy" not in sys.modules:
            raise ImportError
        return real_import(name, *a, **kw)
    monkeypatch.setattr(builtins, "__import__", fake_import)
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
    monkeypatch.setattr(manage_vm, "_wait_for_port", lambda *a, **kw: True)
    _fake_run.calls = []
    _fake_spawn.calls = []
    sys.modules.pop("debugpy", None)
    monkeypatch.setitem(sys.modules, "debugpy", None)
    real_import = builtins.__import__
    def fake_import(name, *a, **kw):
        if name == "debugpy" and "debugpy" not in sys.modules:
            raise ImportError
        return real_import(name, *a, **kw)
    monkeypatch.setattr(builtins, "__import__", fake_import)
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
        or call[0][:4] == ["docker", "compose", "exec", "lockon"]
        for call in _fake_run.calls
    )


def test_vagrant_start_installs_debugpy(monkeypatch):
    calls = []

    def fake_run(cmd, check=True, env=None):
        calls.append(cmd)
        if "python3 -c 'import debugpy'" in " ".join(cmd):
            raise subprocess.CalledProcessError(1, cmd)

    monkeypatch.setattr(manage_vm, "_run", fake_run)
    monkeypatch.setattr(manage_vm, "_spawn", _fake_spawn)
    monkeypatch.setattr(manage_vm, "_wait_for_port", lambda *a, **kw: True)
    monkeypatch.setattr(manage_vm, "which", lambda name: "/bin/vagrant" if name == "vagrant" else None)
    manage_vm.main(["start"])
    assert any("pip3 install --user debugpy" in " ".join(c) for c in calls)


def test_docker_start_installs_debugpy(monkeypatch):
    calls = []

    def fake_run(cmd, check=True, env=None):
        calls.append(cmd)
        if "python" in cmd and "import debugpy" in cmd[-1]:
            raise subprocess.CalledProcessError(1, cmd)

    def fake_which(name):
        if name == "vagrant":
            return None
        return "/bin/docker" if name in {"docker", "docker-compose"} else None

    monkeypatch.setattr(manage_vm, "_run", fake_run)
    monkeypatch.setattr(manage_vm, "_spawn", _fake_spawn)
    monkeypatch.setattr(manage_vm, "_wait_for_port", lambda *a, **kw: True)
    monkeypatch.setattr(manage_vm, "which", fake_which)
    manage_vm.main(["start"])
    assert any("pip" in part for call in calls for part in call)


def test_local_start_without_debugpy(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(manage_vm, "which", lambda name: None)
    monkeypatch.setattr(manage_vm, "_run", _fake_run)
    monkeypatch.setattr(manage_vm, "_spawn", _fake_spawn)
    _fake_run.calls = []
    _fake_spawn.calls = []
    sys.modules.pop("debugpy", None)
    monkeypatch.setenv("LOCKON_LOCAL_PID", str(tmp_path / "pid"))
    monkeypatch.setitem(sys.modules, "debugpy", None)
    real_import = builtins.__import__
    def fake_import(name, *a, **kw):
        if name == "debugpy" and "debugpy" not in sys.modules:
            raise ImportError
        return real_import(name, *a, **kw)
    monkeypatch.setattr(builtins, "__import__", fake_import)
    monkeypatch.setattr(manage_vm, "_port_available", lambda p: True)
    manage_vm.main(["start"])
    out = capsys.readouterr().err
    assert "debugpy not found" in out
    assert any("pip" in part for r in _fake_run.calls for part in r[0])
    assert _fake_spawn.calls


def test_local_halt_and_status(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(manage_vm, "which", lambda name: None)
    monkeypatch.setattr(manage_vm, "_run", _fake_run)
    monkeypatch.setattr(manage_vm, "_spawn", _fake_spawn)
    monkeypatch.setattr(manage_vm, "_wait_for_port", lambda *a, **kw: True)
    monkeypatch.setenv("LOCKON_LOCAL_PID", str(tmp_path / "pid"))
    sys.modules["debugpy"] = types.ModuleType("debugpy")

    monkeypatch.setattr(manage_vm, "_port_available", lambda p: True)
    manage_vm.main(["start"])
    assert (tmp_path / "pid").exists()

    manage_vm.main(["status"])
    out = capsys.readouterr().out
    assert "running" in out

    manage_vm.main(["halt"])
    assert not (tmp_path / "pid").exists()


def test_open_vscode(monkeypatch, tmp_path):
    monkeypatch.setattr(manage_vm, "which", lambda name: None)
    monkeypatch.setattr(manage_vm, "_run", _fake_run)
    monkeypatch.setattr(manage_vm, "_spawn", _fake_spawn)
    monkeypatch.setattr(manage_vm, "_launch_vscode", _fake_launch_vscode)
    monkeypatch.setattr(manage_vm, "_wait_for_port", lambda *a, **kw: True)
    monkeypatch.setenv("LOCKON_LOCAL_PID", str(tmp_path / "pid"))
    sys.modules["debugpy"] = types.ModuleType("debugpy")
    _fake_launch_vscode.calls = []
    manage_vm.main(["start", "--open-vscode"])
    assert _fake_launch_vscode.calls


def test_local_start_port_in_use(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(manage_vm, "which", lambda name: None)
    monkeypatch.setattr(manage_vm, "_run", _fake_run)
    monkeypatch.setattr(manage_vm, "_spawn", _fake_spawn)
    monkeypatch.setattr(manage_vm, "_wait_for_port", lambda *a, **kw: True)
    monkeypatch.setenv("LOCKON_LOCAL_PID", str(tmp_path / "pid"))
    sys.modules["debugpy"] = types.ModuleType("debugpy")
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    monkeypatch.setenv("LOCKON_DEBUG_PORT", str(port))
    try:
        manage_vm.main(["start"])
        err = capsys.readouterr().err
        assert "already in use" in err
    finally:
        sock.close()


def test_wait_for_port_success(monkeypatch):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.listen(1)

    def open_conn():
        with socket.socket() as c:
            c.connect(("127.0.0.1", port))
            c.close()

    t = threading.Timer(0.1, open_conn)
    t.start()
    try:
        assert manage_vm._wait_for_port(port, timeout=1.0, interval=0.05)
    finally:
        sock.close()
        t.cancel()


def test_wait_for_port_timeout():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert not manage_vm._wait_for_port(port, timeout=0.2, interval=0.05)
