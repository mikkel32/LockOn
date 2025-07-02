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


def run_with_spinner(cmd: Iterable[str], message: str = "Working") -> None:
    """Run a command while showing a spinner."""
    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(message, start=False)
        progress.start_task(task)
        try:
            subprocess.check_call(list(cmd))
        except subprocess.CalledProcessError as exc:
            log(f"Command failed: {exc}", level="error")
            raise
        else:
            progress.update(task, completed=1)

