from __future__ import annotations

import platform
import subprocess
from datetime import datetime
from typing import Iterable
import psutil

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from .logger import SecurityLogger

console = Console()
logger = SecurityLogger()


def log(message: str, level: str = "info") -> None:
    """Log a message to the console and security logger."""
    console.log(message)
    getattr(logger, level, logger.info)(message)


def get_system_info() -> str:
    """Return detailed system information."""
    mem = psutil.virtual_memory().total / 1024 ** 3
    return (
        f"Platform: {platform.system()} {platform.release()} ({platform.machine()})\n"
        f"Python: {platform.python_version()}\n"
        f"CPU: {psutil.cpu_count(logical=True)} cores\n"
        f"Memory: {mem:.1f} GB"
    )


def run_with_spinner(
    cmd: Iterable[str],
    message: str = "Working",
    *,
    capture_output: bool = True,
    check: bool = True,
) -> subprocess.CompletedProcess:
    """Run *cmd* while displaying a spinner and return the completed process.

    If ``capture_output`` is True, stdout/stderr are collected so they can be
    logged when the command fails. If ``check`` is True a non-zero exit status
    raises ``CalledProcessError``.
    """
    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(message, start=False)
        progress.start_task(task)
        proc = subprocess.run(list(cmd), text=True, capture_output=capture_output)
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

