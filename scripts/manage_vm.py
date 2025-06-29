#!/usr/bin/env python3
"""Manage the debug environment (Vagrant, Docker, or local)."""
from __future__ import annotations

import argparse
import subprocess
import sys
import os
import signal
from shutil import which
from pathlib import Path


def _run(cmd: list[str], env=None) -> None:
    """Run a command and wait for completion."""
    subprocess.run(cmd, check=True, env=env)


def _spawn(cmd: list[str], env=None) -> subprocess.Popen:
    """Spawn a background process and return the handle."""
    return subprocess.Popen(cmd, env=env)


class Backend:
    """Abstract base class for VM backends."""

    def __init__(self, run=_run, spawn=_spawn) -> None:
        self._run = run
        self._spawn = spawn

    def start(self, provision: bool = False) -> None:  # pragma: no cover - base
        raise NotImplementedError

    def halt(self) -> None:  # pragma: no cover - base
        raise NotImplementedError

    def status(self) -> None:  # pragma: no cover - base
        raise NotImplementedError

    def ssh(self) -> None:  # pragma: no cover - base
        raise NotImplementedError

    def logs(self) -> None:  # pragma: no cover - base
        raise NotImplementedError

    def doctor(self) -> None:  # pragma: no cover - base
        """Verify the debug environment is ready."""
        raise NotImplementedError


class VagrantBackend(Backend):
    """Control the Vagrant VM used for debugging."""

    def start(self, provision: bool = False, port: int = 5678) -> None:
        env = {"LOCKON_DEBUG_PORT": str(port), **os.environ}
        self._run(["vagrant", "up"], env=env)
        if provision:
            self._run(["vagrant", "provision"], env=env)
        self._run([
            "vagrant",
            "ssh",
            "-c",
            "sudo systemctl restart lockon-debug.service",
        ], env=env)
        print(f"VM is running and lockon-debug service is active on port {port}.")
        print("Open VS Code and use the 'Attach to VM' configuration to begin debugging.")

    def halt(self) -> None:
        self._run(["vagrant", "halt"])
        print("VM halted")

    def status(self) -> None:
        self._run(["vagrant", "status"])

    def ssh(self) -> None:
        self._run(["vagrant", "ssh"])

    def logs(self) -> None:
        self._run([
            "vagrant",
            "ssh",
            "-c",
            "journalctl -u lockon-debug.service -n 50 -f",
        ])

    def doctor(self) -> None:
        self._run(["vagrant", "ssh", "-c", "python3 -c 'import debugpy'" ])
        self._run(["vagrant", "ssh", "-c", "systemctl status lockon-debug.service" ])


class DockerBackend(Backend):
    """Control the Docker-based debug environment."""

    def _dc(self, args: list[str], env=None) -> None:
        self._run(["docker-compose", *args], env=env)

    def start(self, provision: bool = False, port: int = 5678) -> None:  # pragma: no cover - simple
        env = {"LOCKON_DEBUG_PORT": str(port), **os.environ}
        self._dc(["up", "--build", "-d"], env=env)
        print(f"Docker container running and debug server exposed on port {port}.")
        print("Attach VS Code using the 'Attach to VM' configuration.")

    def halt(self) -> None:
        self._dc(["down"])
        print("Docker container stopped")

    def status(self) -> None:
        self._dc(["ps"])

    def doctor(self) -> None:
        """Verify debugpy is available and the server is running."""
        self._dc(["exec", "lockon", "python", "-c", "import debugpy"])
        self._dc(["exec", "lockon", "pgrep", "-f", "debug_server.py"])


class LocalBackend(Backend):
    """Run the debug server directly on the host."""

    def __init__(self, run=_run, spawn=_spawn) -> None:
        super().__init__(run, spawn)
        self.pid_file = Path(os.environ.get("LOCKON_LOCAL_PID", "data/local_debug.pid"))

    # Helper to check if the debug server is running
    def _running_pid(self) -> int | None:
        if not self.pid_file.exists():
            return None
        try:
            pid = int(self.pid_file.read_text())
            os.kill(pid, 0)
            return pid
        except Exception:
            try:
                self.pid_file.unlink()
            except FileNotFoundError:
                pass
            return None

    def _ensure_debugpy(self, auto_install: bool = False) -> bool:
        """Return True if debugpy is available."""
        try:
            import debugpy  # noqa: F401
            return True
        except ImportError:
            if not auto_install:
                print(
                    "debugpy is required. Install it with `pip install --user debugpy`.",
                    file=sys.stderr,
                )
                return False
            print("debugpy not found, installing...", file=sys.stderr)
            try:
                self._run(
                    [sys.executable, "-m", "pip", "install", "--user", "debugpy"]
                )
            except subprocess.CalledProcessError as exc:
                print(f"Failed to install debugpy: {exc}", file=sys.stderr)
                return False
            try:
                import debugpy  # noqa: F401
                return True
            except ImportError:
                print("Failed to install debugpy", file=sys.stderr)
                return False

    def start(self, provision: bool = False, port: int = 5678) -> None:
        env = {"LOCKON_DEBUG_PORT": str(port), **os.environ}
        pid = self._running_pid()
        if pid:
            print(f"Local debug server already running (PID {pid})")
            return
        if not self._ensure_debugpy(auto_install=True):
            return
        proc = self._spawn([sys.executable, "debug_server.py", "--port", str(port)], env=env)
        self.pid_file.parent.mkdir(parents=True, exist_ok=True)
        self.pid_file.write_text(str(proc.pid))
        print(f"Local debug server started on port {port} (PID {proc.pid}).")

    def halt(self) -> None:
        pid = self._running_pid()
        if not pid:
            print("Local debug server is not running")
            return
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError as exc:
            print(f"Failed to stop debug server: {exc}", file=sys.stderr)
        else:
            print("Local debug server stopped")
        try:
            self.pid_file.unlink()
        except FileNotFoundError:
            pass

    def status(self) -> None:
        pid = self._running_pid()
        if pid:
            print(f"Local debug server running (PID {pid})")
        else:
            print("Local debug server not running")

    def ssh(self) -> None:
        print("Already running locally; no SSH available.")

    def logs(self) -> None:
        print("Logs are shown in the terminal running the debug server.")

    def doctor(self) -> None:
        if self._ensure_debugpy(auto_install=True):
            print("debugpy installed locally.")
        pid = self._running_pid()
        if pid:
            print(f"Debug server running (PID {pid})")
        else:
            print("Debug server not running")


class EnvironmentManager:
    """Select and operate the best available backend."""

    def __init__(self, run=None, spawn=None, which=None) -> None:
        self._run = run or _run
        self._spawn = spawn or _spawn
        self._which = which or globals()["which"]
        self.backend = self._detect_backend()

    def _detect_backend(self) -> Backend:
        if self._which("vagrant"):
            return VagrantBackend(self._run, self._spawn)
        if self._which("docker") and self._which("docker-compose"):
            return DockerBackend(self._run, self._spawn)
        # Fall back to running locally so tests and development can continue
        return LocalBackend(self._run, self._spawn)

    def start(self, provision: bool = False, port: int = 5678) -> None:
        self.backend.start(provision, port)

    def halt(self) -> None:
        self.backend.halt()

    def status(self) -> None:
        self.backend.status()

    def ssh(self) -> None:
        self.backend.ssh()

    def logs(self) -> None:
        self.backend.logs()

    def doctor(self) -> None:
        self.backend.doctor()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Manage the debug environment (Vagrant, Docker, or local)"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    start_p = sub.add_parser("start", help="Boot the VM and ensure debug service")
    start_p.add_argument("--provision", action="store_true", help="Force reprovisioning")
    start_p.add_argument("--port", type=int, default=int(os.environ.get("LOCKON_DEBUG_PORT", 5678)), help="Port for debugger")

    sub.add_parser("halt", help="Shut down the environment")
    sub.add_parser("status", help="Show environment status")
    sub.add_parser("ssh", help="Open an interactive shell in the environment")
    sub.add_parser("logs", help="Follow debug server logs")
    sub.add_parser("doctor", help="Verify environment is ready for debugging")

    args = parser.parse_args(argv)

    try:
        manager = EnvironmentManager()
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        sys.exit(1)

    try:
        if args.command == "start":
            manager.start(args.provision, args.port)
        elif args.command == "halt":
            manager.halt()
        elif args.command == "status":
            manager.status()
        elif args.command == "ssh":
            manager.ssh()
        elif args.command == "logs":
            manager.logs()
        elif args.command == "doctor":
            manager.doctor()
    except subprocess.CalledProcessError as exc:
        print(f"Command failed: {exc}", file=sys.stderr)
        sys.exit(exc.returncode)


if __name__ == "__main__":
    main()
