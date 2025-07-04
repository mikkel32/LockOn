from __future__ import annotations

import platform
import subprocess
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


def parse_threat_details(
    details: dict | None,
) -> tuple[str | None, str | None, int | None]:
    """Return first snippet, its line number and first YARA match.

    Parameters
    ----------
    details:
        Detection dictionary containing ``snippets`` and ``matches`` lists.

    Returns
    -------
    tuple
        ``(snippet, match, line_number)`` where each element may be ``None`` if
        not present in *details*.
    """

    if not isinstance(details, dict):
        return None, None, None

    snippet: str | None = None
    match: str | None = None
    line: int | None = None

    snips = details.get("snippets") or []
    if snips:
        first = snips[0]
        if isinstance(first, dict):
            snippet = first.get("text")
            line = first.get("line")
        else:
            snippet = str(first)
        if isinstance(snippet, str):
            snippet = snippet.strip()
            if len(snippet) > 120:
                snippet = snippet[:117] + "..."
    matches = details.get("matches") or []
    if matches:
        match = matches[0]

    return snippet, match, line


def highlight(text: str, sub: str, color_code: str = "31") -> str:
    """Return *text* with *sub* wrapped in ANSI color codes.

    If *sub* is not present in *text* no highlighting occurs.
    """
    if not sub or not text:
        return text
    try:
        i = text.index(sub)
    except ValueError:
        return text
    return text[:i] + f"\033[{color_code}m{sub}\033[0m" + text[i + len(sub) :]

