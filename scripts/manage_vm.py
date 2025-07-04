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
import socket
import time

def _launch_vscode(workspace: Path, port: int) -> None:
    """Open VS Code pointing at *workspace* if available."""
    exe = which("code") or which("code-insiders")
    if not exe:
        print("VS Code not found; please open it manually", file=sys.stderr)
        return
    env = os.environ.copy()
    env.setdefault("LOCKON_DEBUG_PORT", str(port))
    try:
        subprocess.run([exe, str(workspace)], env=env, check=True)
    except Exception as exc:
        print(f"Failed to launch VS Code: {exc}", file=sys.stderr)


def _run(cmd: list[str], env=None) -> None:
    """Run a command and wait for completion."""
    subprocess.run(cmd, check=True, env=env)


def _spawn(cmd: list[str], env=None) -> subprocess.Popen:
    """Spawn a background process and return the handle."""
    return subprocess.Popen(cmd, env=env)


def _port_available(port: int) -> bool:
    """Return True if *port* can be bound on localhost."""
    with socket.socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
        return True


def _wait_for_port(
    port: int,
    host: str = "127.0.0.1",
    timeout: float = 5.0,
    interval: float = 0.1,
) -> bool:
    """Return True if *host:port* becomes connectable within *timeout* seconds."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        with socket.socket() as sock:
            try:
                sock.settimeout(interval)
                sock.connect((host, port))
            except OSError:
                time.sleep(interval)
            else:
                return True
    return False


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

    def _ensure_debugpy(self, env) -> None:
        """Install ``debugpy`` in the VM if it's missing."""
        try:
            self._run(["vagrant", "ssh", "-c", "python3 -c 'import debugpy'"], env=env)
        except subprocess.CalledProcessError:
            print("Installing debugpy in VM...", file=sys.stderr)
            self._run(["vagrant", "ssh", "-c", "pip3 install --user debugpy"], env=env)

    def start(self, provision: bool = False, port: int = 5678) -> None:
        env = {"LOCKON_DEBUG_PORT": str(port), **os.environ}
        if not _port_available(port):
            print(f"Port {port} already in use; cannot start debug environment", file=sys.stderr)
            return
        self._run(["vagrant", "up"], env=env)
        if provision:
            self._run(["vagrant", "provision"], env=env)
        self._ensure_debugpy(env)
        self._run(
            [
                "vagrant",
                "ssh",
                "-c",
                "sudo systemctl restart lockon-debug.service",
            ],
            env=env,
        )
        if _wait_for_port(port):
            print(
                f"VM is running and lockon-debug service is active on port {port}."
            )
            print(
                "Open VS Code and use the 'Attach to VM' configuration to begin debugging."
            )
        else:
            print("Debug server failed to start", file=sys.stderr)

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
        env = {"LOCKON_DEBUG_PORT": os.environ.get("LOCKON_DEBUG_PORT", "5678"), **os.environ}
        self._ensure_debugpy(env)
        self._run(["vagrant", "ssh", "-c", "systemctl status lockon-debug.service"], env=env)
        port = int(env["LOCKON_DEBUG_PORT"])
        if _wait_for_port(port):
            print(f"Debug server reachable on port {port}")
        else:
            print(f"Debug server not responding on port {port}", file=sys.stderr)


class DockerBackend(Backend):
    """Control the Docker-based debug environment."""

    def __init__(self, run=_run, spawn=_spawn, which=which) -> None:
        super().__init__(run, spawn)
        if which("docker-compose"):
            self.compose_cmd = ["docker-compose"]
        else:
            self.compose_cmd = ["docker", "compose"]

    def _dc(self, args: list[str], env=None) -> None:
        self._run([*self.compose_cmd, *args], env=env)

    def _ensure_debugpy(self, env) -> None:
        """Install ``debugpy`` in the container if needed."""
        try:
            self._dc(["exec", "lockon", "python", "-c", "import debugpy"], env=env)
        except subprocess.CalledProcessError:
            print("Installing debugpy in container...", file=sys.stderr)
            self._dc(["exec", "lockon", "pip", "install", "--user", "debugpy"], env=env)

    def start(self, provision: bool = False, port: int = 5678) -> None:  # pragma: no cover - simple
        env = {"LOCKON_DEBUG_PORT": str(port), **os.environ}
        if not _port_available(port):
            print(f"Port {port} already in use; cannot start debug environment", file=sys.stderr)
            return
        self._dc(["up", "--build", "-d"], env=env)
        self._ensure_debugpy(env)
        if _wait_for_port(port):
            print(f"Docker container running and debug server exposed on port {port}.")
            print("Attach VS Code using the 'Attach to VM' configuration.")
        else:
            print("Debug server failed to start", file=sys.stderr)

    def halt(self) -> None:
        self._dc(["down"])
        print("Docker container stopped")

    def status(self) -> None:
        self._dc(["ps"])

    def doctor(self) -> None:
        """Verify ``debugpy`` is installed and the server is reachable."""
        env = {"LOCKON_DEBUG_PORT": os.environ.get("LOCKON_DEBUG_PORT", "5678"), **os.environ}
        self._ensure_debugpy(env)
        self._dc(["exec", "lockon", "pgrep", "-f", "debug_server.py"], env=env)
        port = int(env["LOCKON_DEBUG_PORT"])
        if _wait_for_port(port):
            print(f"Debug server reachable on port {port}")
        else:
            print(f"Debug server not responding on port {port}", file=sys.stderr)


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
                import site
                import importlib
                usersite = site.getusersitepackages()
                if usersite not in sys.path:
                    site.addsitedir(usersite)
                importlib.reload(site)
                importlib.invalidate_caches()
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
        if not _port_available(port):
            print(f"Port {port} already in use; cannot start debug server", file=sys.stderr)
            return
        proc = self._spawn([sys.executable, "debug_server.py", "--port", str(port)], env=env)
        self.pid_file.parent.mkdir(parents=True, exist_ok=True)
        self.pid_file.write_text(f"{proc.pid}\n")
        if _wait_for_port(port):
            print(f"Local debug server started on port {port} (PID {proc.pid}).")
        else:
            print(
                f"Debug server failed to start on port {port}",
                file=sys.stderr,
            )

    def halt(self) -> None:
        pid = self._running_pid()
        if not pid:
            print("Local debug server is not running")
            return
        try:
            os.kill(pid, signal.SIGTERM)
            try:
                os.waitpid(pid, 0)
            except OSError:
                # Process is not our child or already reaped
                pass
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
        port = int(os.environ.get("LOCKON_DEBUG_PORT", 5678))
        if pid:
            if _wait_for_port(port):
                print(f"Debug server running (PID {pid}) and reachable on port {port}")
            else:
                print(f"Debug server running (PID {pid}) but port {port} is closed", file=sys.stderr)
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
        if self._which("docker"):
            if self._which("docker-compose"):
                return DockerBackend(self._run, self._spawn)
            try:
                subprocess.run(
                    ["docker", "compose", "version"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=True,
                )
                return DockerBackend(self._run, self._spawn)
            except Exception:
                pass
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
    start_p.add_argument("--open-vscode", action="store_true", help="Launch VS Code after starting")

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
            if args.open_vscode:
                _launch_vscode(Path(__file__).resolve().parent.parent, args.port)
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
