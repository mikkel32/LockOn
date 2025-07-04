import subprocess
from scripts import manage_vm


def test_environment_local_backend():
    mgr = manage_vm.EnvironmentManager(run=lambda *a, **k: None,
                                       spawn=lambda *a, **k: None,
                                       which=lambda c: None)
    assert isinstance(mgr.backend, manage_vm.LocalBackend)


def test_localbackend_start_halt(tmp_path, monkeypatch):
    procs = []

    def spawn(cmd, env=None):
        p = subprocess.Popen(['sleep', '0.1'])
        procs.append(p)
        return p

    backend = manage_vm.LocalBackend(run=lambda *a, **k: None, spawn=spawn)
    backend.pid_file = tmp_path / 'pid'
    monkeypatch.setattr(backend, '_ensure_debugpy', lambda auto_install=False: True)
    backend.start(port=1234)
    assert backend.pid_file.exists()
    backend.halt()
    assert not backend.pid_file.exists()
    for p in procs:
        if p.poll() is None:
            p.kill()
