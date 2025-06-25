from rich.console import Console
from .dashboard import show_dashboard


def main_ui():
    console = Console()
    console.clear()
    show_dashboard(console)
