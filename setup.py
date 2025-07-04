from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
import random
import math
from pathlib import Path
from typing import Iterable


def _bootstrap() -> None:
    """Ensure minimal packages required for the setup script are installed."""
    required = ["rich", "pyyaml", "setuptools"]
    for pkg in required:
        try:
            __import__(pkg)
        except Exception:
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])


_bootstrap()

from rich.text import Text
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TimeElapsedColumn,
)
from rich.panel import Panel
from rich.align import Align
from rich.layout import Layout
from rich.console import Group

from src.utils.helpers import log, get_system_info, run_with_spinner, console
from src.utils.config import ensure_config
from src.utils.rainbow import (
    NeonPulseBorder, MatrixRain, GlitchText, 
    ParticleField, AsciiFireworks
)

MIN_PYTHON = (3, 10)

# Multiple ASCII art variations
LOCKON_ART_3D = r"""
╔═╗     ╔═╗ ╔═╗ ╔═╗ ╦╔═ ╔═╗ ╔╗╔
║ ║     ║ ║ ║   ╠╩╗ ║ ║ ║║║ ║║║
╚═╝═════╚═╝ ╚═╝ ╩ ╩ ╚═╝ ╝╚╝ ╝╚╝
"""

LOCKON_ART_BLOCKS = r"""
▄█       ▄██████▄   ▄████████    ▄█   ▄█▄  ▄██████▄  ███▄▄▄▄   
███      ███    ███ ███    ███   ███ ▄███▀ ███    ███ ███▀▀▀██▄ 
███      ███    ███ ███    █▀    ███▐██▀   ███    ███ ███   ███ 
███      ███    ███ ███         ▄█████▀    ███    ███ ███   ███ 
███      ███    ███ ███        ▀▀█████▄    ███    ███ ███   ███ 
███      ███    ███ ███    █▄    ███▐██▄   ███    ███ ███   ███ 
███▌    ▄███    ███ ███    ███   ███ ▀███▄ ███    ███ ███   ███ 
█████▄▄██ ▀██████▀  ████████▀    ███   ▀█▀  ▀██████▀   ▀█   █▀  
▀                                 ▀                              
"""

LOCKON_ART_CYBER = r"""
┏┓  ┏━┓┏━╸╻┏ ┏━┓┏┓╻
┃   ┃ ┃┃  ┣┻┓┃ ┃┃┗┫
┗┛  ┗━┛┗━╸╹ ╹┗━┛╹ ╹
[SYSTEM.INITIALIZED]
"""

LOCKON_ART_MINIMAL = r"""
 _               _     ___
| |    ___   ___| | __/ _ \ _ __
| |   / _ \ / __| |/ / | | | '_ \
| |__| (_) | (__|   <| |_| | | | |
|_____\___/ \___|_|\_\\___/|_| |_|
"""

# Animated logo parts for assembly effect
LOGO_PARTS = [
    ("╔═╗", 0, 0),
    ("║ ║", 0, 1),
    ("╚═╝", 0, 2),
    ("╔═╗", 5, 0),
    ("║ ║", 5, 1),
    ("╚═╝", 5, 2),
    ("╔═╗", 10, 0),
    ("║  ", 10, 1),
    ("╚═╝", 10, 2),
    ("╔═╗", 15, 0),
    ("╠╩╗", 15, 1),
    ("╩ ╩", 15, 2),
    ("╦╔═", 20, 0),
    ("║ ║", 20, 1),
    ("╚═╝", 20, 2),
    ("╔═╗", 25, 0),
    ("║║║", 25, 1),
    ("╝╚╝", 25, 2),
    ("╔╗╔", 30, 0),
    ("║║║", 30, 1),
    ("╝╚╝", 30, 2),
]


def _cyberpunk_gradient(text: str, offset: int = 0) -> Text:
    """Create a cyberpunk-style gradient with neon colors."""
    result = Text()
    colors = [
        "#ff006e", "#fb5607", "#ffbe0b", "#8338ec", "#3a86ff",
        "#06ffa5", "#ff006e"  # Loop back
    ]
    
    for i, char in enumerate(text):
        if char == ' ':
            result.append(char)
        else:
            pos = ((i + offset) % len(text)) / max(len(text) - 1, 1)
            color_idx = int(pos * (len(colors) - 1))
            color = colors[color_idx]
            
            # Add glow effect randomly
            if random.random() > 0.8:
                result.append(char, style=f"bold {color} on {color}33")
            else:
                result.append(char, style=f"bold {color}")
    
    return result


def _gradient_line(line: str, offset: int = 0) -> Text:
    """Enhanced gradient with multiple color schemes."""
    text = Text()
    n = max(len(line) - 1, 1)
    
    # Choose random gradient style
    gradient_style = random.choice(['neon', 'fire', 'ocean', 'rainbow'])
    
    for i, ch in enumerate(line):
        pos = ((i + offset) % len(line)) / n
        
        if gradient_style == 'neon':
            color = _blend("#00eaff", "#ff00d0", pos)
        elif gradient_style == 'fire':
            if pos < 0.5:
                color = _blend("#ff0000", "#ff8800", pos * 2)
            else:
                color = _blend("#ff8800", "#ffff00", (pos - 0.5) * 2)
        elif gradient_style == 'ocean':
            color = _blend("#001f3f", "#00bfff", pos)
        else:  # rainbow
            hue = pos * 360
            r = int((math.sin(math.radians(hue)) + 1) * 127.5)
            g = int((math.sin(math.radians(hue + 120)) + 1) * 127.5)
            b = int((math.sin(math.radians(hue + 240)) + 1) * 127.5)
            color = f"#{r:02x}{g:02x}{b:02x}"
        
        text.append(ch, style=color)
    
    return text


def _blend(c1: str, c2: str, t: float) -> str:
    c1 = c1.lstrip("#")
    c2 = c2.lstrip("#")
    if len(c1) == 3:
        c1 = "".join(ch * 2 for ch in c1)
    if len(c2) == 3:
        c2 = "".join(ch * 2 for ch in c2)
    r1, g1, b1 = int(c1[0:2], 16), int(c1[2:4], 16), int(c1[4:6], 16)
    r2, g2, b2 = int(c2[0:2], 16), int(c2[2:4], 16), int(c2[4:6], 16)
    r = round(r1 + (r2 - r1) * t)
    g = round(g1 + (g2 - g1) * t)
    b = round(b1 + (b2 - b1) * t)
    return f"#{r:02x}{g:02x}{b:02x}"


def animated_logo_assembly():
    """Assemble the logo piece by piece with effects."""
    console.clear()
    grid = [[' ' for _ in range(35)] for _ in range(3)]
    
    for part, x, y in LOGO_PARTS:
        # Add each part with a flash effect
        for i, char in enumerate(part):
            if 0 <= y < 3 and 0 <= x + i < 35:
                grid[y][x + i] = char
        
        # Render current state with effects
        console.clear()
        for row_idx, row in enumerate(grid):
            line = ''.join(row)
            console.print(_cyberpunk_gradient(line, row_idx * 5), justify="center")
        
        time.sleep(0.05)
    
    # Final flash effect
    for _ in range(3):
        console.clear()
        time.sleep(0.1)
        for row in grid:
            line = ''.join(row)
            console.print(Text(line, style="bold white on cyan"), justify="center")
        time.sleep(0.1)


def matrix_intro():
    """Show a Matrix-style rain intro."""
    matrix = MatrixRain(width=80, height=20)
    
    for step in range(50):
        console.clear()
        console.print(matrix.render(step))
        
        # Gradually reveal the logo
        if step > 25:
            opacity = (step - 25) / 25
            logo_lines = LOCKON_ART_CYBER.strip().split('\n')
            y_offset = 8
            
            for i, line in enumerate(logo_lines):
                if random.random() < opacity:
                    console.print(
                        _cyberpunk_gradient(line, step),
                        justify="center",
                        style=f"bold"
                    )
        
        time.sleep(0.05)


def fireworks_celebration():
    """Display a fireworks show."""
    fw = AsciiFireworks(width=console.width, height=25)
    
    for step in range(100):
        fw.launch()
        fw.update()
        
        console.clear()
        console.print(fw.render())
        
        # Show success message in the middle
        if step > 30:
            console.print("\n" * 10)
            console.print(
                Align.center(
                    Text("✨ INSTALLATION COMPLETE! ✨", style="bold green"),
                    vertical="middle"
                )
            )
        
        time.sleep(0.05)


def show_setup_banner() -> None:
    """Enhanced setup banner with multiple effects."""
    
    # Choose random intro effect
    intro_effects = [
        ("matrix", matrix_intro),
        ("assembly", animated_logo_assembly),
        ("classic", lambda: classic_gradient_intro()),
        ("glitch", lambda: glitch_intro()),
        ("particle", lambda: particle_intro())
    ]
    
    effect_name, effect_func = random.choice(intro_effects)
    
    # Run the chosen effect
    effect_func()
    
    # Show loading progress with custom animation
    with Progress(
        SpinnerColumn(style="bold magenta"),
        "[progress.description]{task.description}",
        BarColumn(bar_width=None),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("🚀 Initializing LockOn", total=100)
        
        for i in range(100):
            progress.update(task, advance=1)
            
            # Update description with fun messages
            if i == 25:
                progress.update(task, description="🔧 Configuring quantum flux capacitor")
            elif i == 50:
                progress.update(task, description="⚡ Charging neon circuits")
            elif i == 75:
                progress.update(task, description="🌟 Activating hyperdrive")
            
            time.sleep(0.02)
    
    # Final banner
    console.rule("[bold cyan]═══ LockOn Setup Complete ═══")
    console.print()


def classic_gradient_intro():
    """Classic gradient animation with enhancements."""
    lines = LOCKON_ART_MINIMAL.strip("\n").splitlines()
    
    with NeonPulseBorder(speed=0.05, effect="rainbow"):
        for step in range(30):
            console.clear()
            
            # Add particle effects behind text
            particles = ParticleField(width=console.width, height=len(lines) + 4, particles=30)
            particles.update()
            console.print(particles.render())
            
            console.print()  # Spacing
            
            for line in lines:
                console.print(_gradient_line(line, step), justify="center")
            
            time.sleep(0.05)


def glitch_intro():
    """Glitch effect intro."""
    logo_lines = LOCKON_ART_BLOCKS.strip().split('\n')
    
    for intensity in [0.8, 0.6, 0.4, 0.2, 0.1, 0.05, 0]:
        console.clear()
        
        for line in logo_lines:
            if intensity > 0:
                console.print(
                    Align.center(
                        GlitchText.glitch(line, intensity),
                        vertical="middle",
                    )
                )
            else:
                console.print(
                    Align.center(
                        _cyberpunk_gradient(line),
                        vertical="middle",
                    )
                )
        
        time.sleep(0.2)


def particle_intro():
    """Particle field intro."""
    particles = ParticleField(width=console.width, height=console.height - 5, particles=100)
    logo_lines = LOCKON_ART_3D.strip().split('\n')
    
    for step in range(40):
        console.clear()
        
        # Update and render particles
        particles.update()
        console.print(particles.render())
        
        # Overlay logo with increasing opacity
        if step > 10:
            console.print("\n" * 8)  # Position logo
            for line in logo_lines:
                console.print(
                    Align.center(
                        _cyberpunk_gradient(line, step),
                        vertical="middle",
                    )
                )
        
        time.sleep(0.05)


def check_python_version() -> None:
    if sys.version_info < MIN_PYTHON:
        sys.exit(f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} or newer required.")


def locate_root(start: Path | None = None) -> Path:
    start = (start or Path(__file__)).resolve()
    if start.is_file():
        start = start.parent
    for path in [start, *start.parents]:
        if (path / ".git").is_dir() or (path / "requirements.txt").is_file():
            return path
    return start


def update_repo() -> None:
    os.chdir(ROOT_DIR)
    if not (ROOT_DIR / ".git").is_dir():
        log("No git repository found; skipping update check.")
        return
    try:
        branch = subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"], text=True
        ).strip()
        upstream = subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
            text=True,
        ).strip()
        remote, remote_branch = upstream.split("/", 1)
        try:
            with NeonPulseBorder(effect="wave"):
                run_with_spinner(
                    ["git", "fetch", remote],
                    message="🌐 Fetching updates from the matrix",
                )
        except subprocess.CalledProcessError as exc:
            log(f"Failed to fetch updates: {exc}")
            return
        ahead_behind = subprocess.check_output(
            [
                "git",
                "rev-list",
                "--left-right",
                "--count",
                f"{branch}...{remote}/{remote_branch}",
            ],
            text=True,
        ).strip()
        ahead, behind = map(int, ahead_behind.split())
        if behind:
            log(f"Repository behind upstream by {behind} commit(s); pulling...")
            with NeonPulseBorder(effect="pulse"):
                run_with_spinner(
                    ["git", "pull", "--ff-only", remote, remote_branch],
                    message="⬇️  Downloading updates",
                )
            log("✅ Repository updated.")
        else:
            log("✨ Repository is up to date.")
    except Exception as exc:
        log(f"Failed to update repository: {exc}")


def get_root() -> Path:
    env = os.environ.get("LOCKON_ROOT")
    if env:
        return Path(env).expanduser().resolve()
    try:
        out = subprocess.check_output([
            "git",
            "rev-parse",
            "--show-toplevel",
        ], cwd=Path(__file__).resolve().parent, text=True).strip()
        return Path(out)
    except Exception:
        return locate_root()


ROOT_DIR = get_root()


def get_venv_dir() -> Path:
    env = os.environ.get("LOCKON_VENV")
    if env:
        return Path(env).expanduser().resolve()
    return ROOT_DIR / ".venv"


REQUIREMENTS_FILE = ROOT_DIR / "requirements.txt"
EXTRAS_FILE = ROOT_DIR / "requirements-optional.txt"
VENV_DIR = get_venv_dir()
DEV_PACKAGES = ["debugpy", "flake8"]


def ensure_venv(venv_dir: Path = VENV_DIR, *, python: str | None = None) -> Path:
    if sys.prefix != sys.base_prefix:
        return Path(sys.executable)

    if not venv_dir.exists():
        py_exe = python or sys.executable
        log(f"🏗️  Creating virtual environment at {venv_dir} using {py_exe}")
        with NeonPulseBorder(effect="rainbow"):
            run_with_spinner([py_exe, "-m", "venv", str(venv_dir)], message="🌈 Creating virtualenv")

    python_path = venv_dir / "bin" / "python"
    if not python_path.exists():
        python_path = venv_dir / "Scripts" / "python.exe"
    return python_path


def _pip(args: Iterable[str], python: Path | None = None, *, upgrade_pip: bool = False) -> None:
    py = python or ensure_venv()
    if upgrade_pip:
        with NeonPulseBorder(effect="wave"):
            run_with_spinner([str(py), "-m", "pip", "install", "--upgrade", "pip"], message="⬆️  Upgrading pip")
    cmd = [str(py), "-m", "pip", *args]
    log("🔧 Running: " + " ".join(cmd))
    with NeonPulseBorder(effect="pulse"):
        run_with_spinner(cmd, message="📦 Installing dependencies")


def run_tests(extra: Iterable[str] | None = None) -> None:
    python = ensure_venv()
    cmd = [str(python), "-m", "pytest", "-q"]
    if extra:
        cmd.extend(extra)
    log("🧪 Running: " + " ".join(cmd))
    subprocess.check_call(cmd)


def freeze_requirements(output: Path = ROOT_DIR / "requirements.lock") -> None:
    """Write installed packages to a lock file."""
    python = ensure_venv()
    log(f"🧊 Freezing installed packages to {output}")
    with open(output, "w") as fh:
        subprocess.check_call([str(python), "-m", "pip", "freeze"], stdout=fh)


def ensure_requirements(req_path: Path = REQUIREMENTS_FILE) -> None:
    """Ensure all packages from *req_path* are installed."""
    import pkg_resources

    if not req_path.is_file():
        log(f"📄 Requirements file {req_path} not found")
        return

    for line in req_path.read_text().splitlines():
        req = line.strip()
        if not req or req.startswith("#"):
            continue
        try:
            pkg_resources.require(req)
        except (pkg_resources.DistributionNotFound, pkg_resources.VersionConflict):
            log(f"⚠️  Installing missing or outdated package: {req}", level="warning")
            _pip(["install", req])


def install(
    requirements: Path | None = None,
    *,
    dev: bool = False,
    upgrade: bool = False,
    extras: bool = False,
    skip_update: bool = False,
) -> None:
    os.chdir(ROOT_DIR)
    if not skip_update:
        update_repo()
    py = ensure_venv()
    req_path = requirements or REQUIREMENTS_FILE
    if req_path.is_file():
        log(f"📦 Installing requirements from {req_path}")
        args = ["install", "-r", str(req_path)]
        if upgrade:
            args.append("--upgrade")
        _pip(args, python=py, upgrade_pip=upgrade)
        ensure_requirements(req_path)
    else:
        log(f"📄 Requirements file {req_path} not found")

    if extras and EXTRAS_FILE.is_file():
        log(f"✨ Installing optional packages from {EXTRAS_FILE}")
        args = ["install", "-r", str(EXTRAS_FILE)]
        if upgrade:
            args.append("--upgrade")
        _pip(args, python=py)
        ensure_requirements(EXTRAS_FILE)

    if dev:
        log("🛠️  Installing development packages")
        for pkg in DEV_PACKAGES:
            args = ["install", pkg]
            if upgrade:
                args.append("--upgrade")
            _pip(args, python=py)

    ensure_config()
    
    # Show completion animation
    fireworks_celebration()
    
    log("✅ Dependencies installed successfully!")


def check_outdated(requirements: Path | None = None, *, upgrade: bool = False) -> None:
    os.chdir(ROOT_DIR)
    req_path = requirements or REQUIREMENTS_FILE
    if not req_path.is_file():
        log(f"📄 Requirements file {req_path} not found")
        return
    result = subprocess.run(
        [sys.executable, "-m", "pip", "list", "--outdated", "--format=json"],
        capture_output=True,
        text=True,
        check=False,
    )
    try:
        pkgs = [f"{p['name']} {p['version']} -> {p['latest_version']}" for p in __import__('json').loads(result.stdout)]
    except Exception:
        pkgs = []
    if pkgs:
        log("📊 Packages with updates available:\n" + "\n".join(pkgs))
        if upgrade:
            log("⬆️  Upgrading packages...")
            names = [p.split()[0] for p in pkgs]
            _pip(["install", "--upgrade", *names])
    else:
        log("✨ All packages up to date.")


def show_info() -> None:
    # Create a fancy info panel
    info_text = f"""
🏠 Project Root: {ROOT_DIR}
🐍 Virtualenv: {VENV_DIR}
{get_system_info()}
    """
    
    panel = Panel(
        Align.center(Text(info_text.strip(), style="cyan")),
        title="[bold magenta]LockOn System Information",
        border_style="bright_blue",
        padding=(1, 2),
    )
    
    console.print(panel)


def doctor() -> None:
    """Verify Python version and required packages."""
    check_python_version()
    ensure_venv()
    ensure_config()
    check_outdated()
    ensure_requirements()
    freeze_requirements()
    
    # Success animation
    console.print()
    console.print(
        Panel(
            Align.center(Text("✅ Environment looks good!", style="bold green")),
            border_style="green",
            padding=(1, 2),
        )
    )


if __name__ == "__main__":
    show_setup_banner()
    check_python_version()
    parser = argparse.ArgumentParser(description="Manage LockOn dependencies and show environment info")
    sub = parser.add_subparsers(dest="command")

    install_p = sub.add_parser("install", help="Install required packages")
    install_p.add_argument("--requirements", type=Path, help="Path to an alternate requirements file")
    install_p.add_argument("--dev", action="store_true", help="Install development packages")
    install_p.add_argument("--upgrade", action="store_true", help="Upgrade packages to latest versions")
    install_p.add_argument("--extras", action="store_true", help="Install optional packages as well")
    install_p.add_argument("--skip-update", action="store_true", help="Skip pulling the latest git changes before installing")

    check_p = sub.add_parser("check", help="List outdated packages")
    check_p.add_argument("--requirements", type=Path, help="Path to the requirements file")

    sub.add_parser("info", help="Show system information")
    sub.add_parser("doctor", help="Verify Python and package setup")
    venv_p = sub.add_parser("venv", help="Create or ensure the project virtualenv")
    venv_p.add_argument("--recreate", action="store_true", help="Recreate the virtual environment")
    sub.add_parser("clean", help="Remove the project virtualenv")
    sub.add_parser("update", help="Pull the latest changes from the repository")
    sub.add_parser("upgrade", help="Upgrade all outdated packages")
    test_p = sub.add_parser("test", help="Run the test suite")
    test_p.add_argument("extra", nargs="*", help="Additional pytest arguments")
    freeze_p = sub.add_parser("freeze", help="Write installed packages to a lock file")
    freeze_p.add_argument("--output", type=Path, default=ROOT_DIR / "requirements.lock", help="Output lock file")

    args = parser.parse_args()
    if args.command == "check":
        check_outdated(requirements=args.requirements)
    elif args.command == "upgrade":
        check_outdated(requirements=None, upgrade=True)
    elif args.command == "info":
        show_info()
    elif args.command == "doctor":
        doctor()
    elif args.command == "venv":
        if args.recreate and VENV_DIR.exists():
            import shutil
            shutil.rmtree(VENV_DIR)
        ensure_venv()
    elif args.command == "clean":
        import shutil
        if VENV_DIR.exists():
            shutil.rmtree(VENV_DIR)
            log("✅ Virtualenv removed.")
        else:
            log("❌ No virtualenv to remove.")
    elif args.command == "test":
        run_tests(args.extra)
    elif args.command == "freeze":
        freeze_requirements(args.output)
    elif args.command == "update":
        update_repo()
    else:
        install(
            requirements=getattr(args, "requirements", None),
            dev=getattr(args, "dev", False),
            upgrade=getattr(args, "upgrade", False),
            extras=getattr(args, "extras", False),
            skip_update=getattr(args, "skip_update", False),
        )
