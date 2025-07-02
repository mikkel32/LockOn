from __future__ import annotations

import threading
import time
from contextlib import ContextDecorator
from rich.console import Console
from rich.live import Live
from rich.text import Text

console = Console()


class NeonPulseBorder(ContextDecorator):
    """Animated neon border used during setup."""

    def __init__(self, speed: float = 0.1, width: int = 60) -> None:
        self.speed = speed
        self.width = width
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def __enter__(self):
        self._thread = threading.Thread(target=self._animate, daemon=True)
        self._thread.start()
        return self

    def _animate(self) -> None:
        step = 0
        with Live(console=console, refresh_per_second=30):
            while not self._stop.is_set():
                color = "#ff00d0" if step % 2 else "#00eaff"
                console.rule(Text(" " * self.width, style=color))
                step += 1
                time.sleep(self.speed)

    def __exit__(self, exc_type, exc, tb):
        self._stop.set()
        if self._thread:
            self._thread.join()
        console.rule("[bold magenta]")
        return False

