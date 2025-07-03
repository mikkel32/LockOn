"""Windows privilege helpers used by LockOn."""
from __future__ import annotations

import sys
import os
import getpass
from typing import Iterable, List
import threading
import time

_win = sys.platform.startswith("win32")

if _win:
    import ctypes
    from ctypes import wintypes
    from utils.paths import resource_path

    _native = None
    try:
        dll_path = resource_path("native", "privileges.dll")
        if dll_path.exists():
            _native = ctypes.WinDLL(str(dll_path))
            _native.ElevatePrivilegesAndImpersonate.restype = wintypes.BOOL
            _native.GetCurrentSessionId.restype = wintypes.DWORD
            _native.HasPrivilege.argtypes = [wintypes.LPCWSTR]
            _native.HasPrivilege.restype = wintypes.BOOL
    except Exception:
        _native = None

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    TOKEN_ADJUST_PRIVILEGES = 0x20
    TOKEN_QUERY = 0x8
    TOKEN_DUPLICATE = 0x2
    TOKEN_ALL_ACCESS = 0xF01FF
    SE_PRIVILEGE_ENABLED = 0x2

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [
            ("PrivilegeCount", wintypes.DWORD),
            ("Privileges", LUID_AND_ATTRIBUTES * 1),
        ]

    def _running_as_system() -> bool:
        try:
            user = os.environ.get("USERNAME") or getpass.getuser()
        except Exception:
            user = ""
        return user.lower() == "system"

    def _get_handle(access: int) -> wintypes.HANDLE:
        handle = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), access, ctypes.byref(handle)):
            return wintypes.HANDLE()
        return handle

    def adjust_privileges(priv_names: Iterable[str]) -> bool:
        names = list(priv_names)
        if not names:
            return False
        htoken = _get_handle(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY)
        if not htoken:
            return False
        for name in names:
            luid = LUID()
            if advapi32.LookupPrivilegeValueW(None, wintypes.LPCWSTR(name), ctypes.byref(luid)):
                tp = TOKEN_PRIVILEGES()
                tp.PrivilegeCount = 1
                tp.Privileges[0].Luid = luid
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
                advapi32.AdjustTokenPrivileges(htoken, False, ctypes.byref(tp), ctypes.sizeof(tp), None, None)
        kernel32.CloseHandle(htoken)
        return ctypes.get_last_error() == 0

    def enable_impersonation() -> bool:
        htoken = _get_handle(TOKEN_DUPLICATE | TOKEN_QUERY)
        if not htoken:
            return False
        dup = wintypes.HANDLE()
        if not advapi32.DuplicateTokenEx(htoken, TOKEN_ALL_ACCESS, None, 2, 2, ctypes.byref(dup)):
            kernel32.CloseHandle(htoken)
            return False
        ok = advapi32.ImpersonateLoggedOnUser(dup)
        kernel32.CloseHandle(dup)
        kernel32.CloseHandle(htoken)
        return bool(ok)

    def elevate_privileges_and_impersonate() -> bool:
        privs = [
            "SeDebugPrivilege",
            "SeImpersonatePrivilege",
            "SeAssignPrimaryTokenPrivilege",
            "SeIncreaseQuotaPrivilege",
            "SeTcbPrivilege",
        ]
        adjust_privileges(privs)
        if not _running_as_system():
            return True
        if _native:
            try:
                return bool(_native.ElevatePrivilegesAndImpersonate())
            except Exception:
                pass
        return enable_impersonation()

    def get_current_session_id() -> int:
        if _native:
            try:
                return int(_native.GetCurrentSessionId())
            except Exception:
                pass
        sess = wintypes.DWORD()
        advapi32.ProcessIdToSessionId(kernel32.GetCurrentProcessId(), ctypes.byref(sess))
        return int(sess.value)

    def has_privilege(priv_name: str) -> bool:
        if _native:
            try:
                return bool(_native.HasPrivilege(wintypes.LPCWSTR(priv_name)))
            except Exception:
                pass
        htoken = _get_handle(TOKEN_QUERY)
        if not htoken:
            return False
        size = wintypes.DWORD()
        advapi32.GetTokenInformation(htoken, 3, None, 0, ctypes.byref(size))
        if ctypes.get_last_error() != 122:
            kernel32.CloseHandle(htoken)
            return False
        buf = (ctypes.c_byte * size.value)()
        if not advapi32.GetTokenInformation(htoken, 3, ctypes.byref(buf), size, ctypes.byref(size)):
            kernel32.CloseHandle(htoken)
            return False
        privileges = ctypes.cast(buf, ctypes.POINTER(TOKEN_PRIVILEGES)).contents
        luid = LUID()
        advapi32.LookupPrivilegeValueW(None, wintypes.LPCWSTR(priv_name), ctypes.byref(luid))
        for i in range(privileges.PrivilegeCount):
            attr = privileges.Privileges[i]
            if attr.Luid.LowPart == luid.LowPart and attr.Luid.HighPart == luid.HighPart:
                kernel32.CloseHandle(htoken)
                return bool(attr.Attributes & SE_PRIVILEGE_ENABLED)
        kernel32.CloseHandle(htoken)
        return False

    class PrivilegeManager:
        """High level privilege handler with optional background verification."""

        def __init__(
            self,
            privs: Iterable[str] | None = None,
            auto_acquire: bool = False,
            impersonate: bool = True,
            auto_monitor: bool = False,
            interval: float = 60.0,
        ) -> None:
            self.requested: List[str] = list(privs or [])
            self._monitor_thread = None
            self._monitor_running = False
            self.missing: List[str] = []
            self._monitor_thread: threading.Thread | None = None
            self._monitor_running = False
            self.interval = interval
            if auto_acquire:
                self.ensure(self.requested or ALL_PRIVILEGES, impersonate)
            if auto_monitor:
                self.start_monitor(self.requested or ALL_PRIVILEGES, impersonate, interval)

        def acquire(self, privs: Iterable[str] = None, impersonate: bool = True) -> List[str]:
            privs = list(privs or ALL_PRIVILEGES)
            if privs:
                adjust_privileges(privs)
            if impersonate:
                elevate_privileges_and_impersonate()
            return self.verify(privs)

        def verify(self, privs: Iterable[str]) -> List[str]:
            return [p for p in privs if not has_privilege(p)]

        def ensure(self, privs: Iterable[str] = None, impersonate: bool = True) -> List[str]:
            privs = list(privs or ALL_PRIVILEGES)
            self.missing = self.acquire(privs, impersonate)
            return self.missing

        def ensure_active(self, privs: Iterable[str] = None, impersonate: bool = True) -> List[str]:
            """Verify and reacquire *privs* if they have dropped."""
            privs = list(privs or ALL_PRIVILEGES)
            missing = self.verify(privs)
            if missing:
                missing = self.acquire(missing, impersonate)
            return missing

        def use(self, privs: Iterable[str], impersonate: bool = True):
            class _Ctx:
                def __enter__(inner):
                    self.ensure(privs, impersonate)
                    return self

                def __exit__(inner, exc_type, exc, tb):
                    return False

            return _Ctx()

        def start_monitor(
            self,
            privs: Iterable[str] | None = None,
            impersonate: bool = True,
            interval: float | None = None,
        ) -> None:
            """Start a background thread that periodically rechecks privileges."""
            if self._monitor_running:
                return
            self._monitor_running = True
            self._monitor_privs = list(privs or self.requested or ALL_PRIVILEGES)
            self._monitor_impersonate = impersonate
            self.interval = interval or self.interval
            self._monitor_thread = threading.Thread(
                target=self._monitor_loop, daemon=True, name="PrivilegeMonitor"
            )
            self._monitor_thread.start()

        def stop_monitor(self) -> None:
            """Stop the background privilege monitor."""
            self._monitor_running = False
            if self._monitor_thread:
                self._monitor_thread.join()
                self._monitor_thread = None

        def _monitor_loop(self) -> None:
            while self._monitor_running:
                try:
                    self.ensure_active(
                        self._monitor_privs, impersonate=self._monitor_impersonate
                    )
                except Exception:
                    pass
                time.sleep(self.interval)
else:
    def adjust_privileges(priv_names: Iterable[str]) -> bool:
        return False

    def enable_impersonation() -> bool:
        return False

    def _running_as_system() -> bool:
        return os.geteuid() == 0

    def elevate_privileges_and_impersonate() -> bool:
        return False

    def get_current_session_id() -> int:
        return -1

    def has_privilege(priv_name: str) -> bool:
        return False

    class PrivilegeManager:
        """Stubbed privilege manager for non-Windows platforms."""

        def __init__(
            self,
            privs: Iterable[str] | None = None,
            auto_acquire: bool = False,
            impersonate: bool = True,
            auto_monitor: bool = False,
            interval: float = 60.0,
        ) -> None:
            self.requested: List[str] = list(privs or [])

        def acquire(self, privs: Iterable[str] = None, impersonate: bool = True) -> List[str]:
            return []

        def verify(self, privs: Iterable[str]) -> List[str]:
            return []

        def ensure(self, privs: Iterable[str] = None, impersonate: bool = True) -> List[str]:
            return []

        def ensure_active(self, privs: Iterable[str] = None, impersonate: bool = True) -> List[str]:
            return []

        def use(self, privs: Iterable[str], impersonate: bool = True):
            class _Ctx:
                def __enter__(inner):
                    return self

                def __exit__(inner, exc_type, exc, tb):
                    return False

            return _Ctx()

        def start_monitor(self, privs: Iterable[str] | None = None, impersonate: bool = True, interval: float | None = None) -> None:
            self._monitor_running = True
            self._monitor_privs = list(privs or self.requested)
            self._monitor_impersonate = impersonate
            self.interval = interval or 60.0
            self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self._monitor_thread.start()

        def stop_monitor(self) -> None:
            self._monitor_running = False
            if self._monitor_thread:
                self._monitor_thread.join()
                self._monitor_thread = None

        def _monitor_loop(self) -> None:
            while self._monitor_running:
                try:
                    self.ensure_active(self._monitor_privs, impersonate=self._monitor_impersonate)
                except Exception:
                    pass
                time.sleep(self.interval)

ALL_PRIVILEGES = [
    "SeDebugPrivilege",
    "SeShutdownPrivilege",
    "SeTcbPrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeTakeOwnershipPrivilege",
    "SeLoadDriverPrivilege",
    "SeSystemtimePrivilege",
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeIncreaseQuotaPrivilege",
    "SeSecurityPrivilege",
    "SeSystemEnvironmentPrivilege",
    "SeChangeNotifyPrivilege",
    "SeRemoteShutdownPrivilege",
    "SeUndockPrivilege",
    "SeSyncAgentPrivilege",
    "SeEnableDelegationPrivilege",
    "SeManageVolumePrivilege",
    "SeImpersonatePrivilege",
    "SeCreateGlobalPrivilege",
    "SeAuditPrivilege",
    "SeSystemProfilePrivilege",
]

def require_privileges(privs: Iterable[str], impersonate: bool = True):
    """Decorator to ensure *privs* before calling the wrapped function."""

    def decorator(func):
        def wrapper(self, *args, **kwargs):
            pm = getattr(self, "priv_manager", None)
            if pm is None:
                pm = PrivilegeManager()
            missing = pm.ensure(privs, impersonate)
            if missing and sys.platform == "win32":
                log = getattr(self, "logger", None)
                if log:
                    log.error(f"Missing privilege: {', '.join(missing)}")
                raise PermissionError(
                    f"Required privileges missing: {', '.join(missing)}"
                )
            return func(self, *args, **kwargs)

        return wrapper

    return decorator
