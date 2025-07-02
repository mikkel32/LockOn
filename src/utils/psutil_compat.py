try:  # pragma: no cover - optional dependency
    import psutil as _psutil  # type: ignore
    psutil = _psutil
    HAS_PSUTIL = True
except Exception:  # pragma: no cover - simple fallback
    import os
    from types import SimpleNamespace

    class _Proc:
        def __init__(self, pid: int):
            self.pid = pid
        def name(self):
            return f"process{self.pid}"
        def terminate(self):
            pass
        def wait(self, timeout=None):
            pass
        def kill(self):
            pass
        def parent(self):
            return None
        @property
        def info(self):
            return {"name": self.name(), "pid": self.pid, "cpu_percent": 0}
        @property
        def open_files(self):
            return []

    def process_iter(attrs=None):
        return []

    def cpu_count(logical=True):
        return os.cpu_count() or 1

    class _VMem:
        def __init__(self):
            self.total = 0
    def virtual_memory():
        return _VMem()

    class NoSuchProcess(Exception):
        pass
    class AccessDenied(Exception):
        pass

    psutil = SimpleNamespace(
        Process=_Proc,
        process_iter=process_iter,
        cpu_count=cpu_count,
        virtual_memory=virtual_memory,
        NoSuchProcess=NoSuchProcess,
        AccessDenied=AccessDenied,
    )
    HAS_PSUTIL = False

__all__ = ["psutil", "HAS_PSUTIL"]
