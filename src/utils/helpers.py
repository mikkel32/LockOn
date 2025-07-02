from __future__ import annotations

import platform
import subprocess
from datetime import datetime
from typing import Iterable
from .psutil_compat import psutil

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from .logger import SecurityLogger

console = Console()
logger = SecurityLogger()


def format_bytes(size: int) -> str:
    """Return human readable file size."""
    units = ["B", "KB", "MB", "GB", "TB"]
    for unit in units:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


def log(message: str, level: str = "info") -> None:
    """Log a message to the console and security logger."""
    console.log(message)
    getattr(logger, level, logger.info)(message)


def get_system_info() -> str:
    """Return detailed system information."""
    mem = psutil.virtual_memory().total
    cpu = psutil.cpu_count(logical=True)
    freq = getattr(psutil, "cpu_freq", lambda: None)()
    freq_str = f" @ {freq.current/1000:.2f}GHz" if freq else ""
    return (
        f"Platform: {platform.system()} {platform.release()} ({platform.machine()})\n"
        f"Python: {platform.python_version()}\n"
        f"CPU: {cpu} cores{freq_str}\n"
        f"Memory: {format_bytes(int(mem))}"
    )


def run_with_spinner(
    cmd: Iterable[str],
    message: str = "Working",
    *,
    capture_output: bool = True,
    check: bool = True,
    timeout: float | None = None,
) -> subprocess.CompletedProcess:
    """Run *cmd* while displaying a spinner and return the completed process.

    Parameters
    ----------
    cmd : Iterable[str]
        Command and arguments to execute.
    message : str
        Message shown alongside the spinner.
    capture_output : bool, optional
        Capture stdout/stderr for logging, by default ``True``.
    check : bool, optional
        Raise ``CalledProcessError`` if the command exits with a non-zero
        status, by default ``True``.
    timeout : float | None, optional
        If provided, terminate the command after ``timeout`` seconds.

    Returns
    -------
    subprocess.CompletedProcess
        Completed process object as returned by ``subprocess.run``.
    """
    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(message, start=False)
        progress.start_task(task)
        proc = subprocess.run(
            list(cmd),
            text=True,
            capture_output=capture_output,
            timeout=timeout,
        )
        progress.update(task, completed=1)

    if proc.returncode != 0:
        log(f"Command failed ({proc.returncode}): {' '.join(cmd)}", level="error")
        if capture_output:
            if proc.stdout:
                log(proc.stdout.strip())
            if proc.stderr:
                log(proc.stderr.strip(), level="error")
        if check:
            proc.check_returncode()

    return proc

