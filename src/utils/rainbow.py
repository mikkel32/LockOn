from __future__ import annotations

import threading
import time
import random
import math
from contextlib import ContextDecorator
from rich.console import Console
from rich.live import Live
from rich.text import Text

console = Console()


class NeonPulseBorder(ContextDecorator):
    """Animated neon border with multiple effects."""

    def __init__(self, speed: float = 0.1, width: int = 60, effect: str = "pulse") -> None:
        self.speed = speed
        self.width = width
        self.effect = effect
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def __enter__(self):
        self._thread = threading.Thread(target=self._animate, daemon=True)
        self._thread.start()
        return self

    def _get_rainbow_color(self, position: float) -> str:
        """Generate smooth rainbow colors."""
        hue = position * 360
        r = int((math.sin(math.radians(hue)) + 1) * 127.5)
        g = int((math.sin(math.radians(hue + 120)) + 1) * 127.5)
        b = int((math.sin(math.radians(hue + 240)) + 1) * 127.5)
        return f"#{r:02x}{g:02x}{b:02x}"

    def _get_wave_pattern(self, step: int, width: int) -> str:
        """Create a wave pattern border."""
        pattern = ""
        for i in range(width):
            wave_pos = math.sin((i + step) * 0.3) * 2
            char = "━" if wave_pos > 0 else "─"
            color = self._get_rainbow_color((i + step) / width)
            pattern += f"[{color}]{char}[/]"
        return pattern

    def _animate(self) -> None:
        step = 0
        with Live(console=console, refresh_per_second=30):
            while not self._stop.is_set():
                if self.effect == "pulse":
                    # Original pulse effect with gradient
                    intensity = (math.sin(step * 0.2) + 1) / 2
                    r = int(255 * intensity)
                    g = int(234 * (1 - intensity))
                    b = int(255 * (1 - intensity))
                    color = f"#{r:02x}{g:02x}{b:02x}"
                    console.rule(Text("═" * self.width, style=f"{color} bold"))
                elif self.effect == "wave":
                    # Wave pattern
                    console.print(self._get_wave_pattern(step, self.width), justify="center")
                elif self.effect == "rainbow":
                    # Smooth rainbow gradient
                    border = ""
                    for i in range(self.width):
                        color = self._get_rainbow_color((i + step * 2) / self.width)
                        border += f"[{color}]▓[/]"
                    console.print(border, justify="center")
                
                step += 1
                time.sleep(self.speed)

    def __exit__(self, exc_type, exc, tb):
        self._stop.set()
        if self._thread:
            self._thread.join()
        console.rule("[bold magenta]")
        return False


class MatrixRain:
    """Matrix-style digital rain effect."""
    
    def __init__(self, width: int = 80, height: int = 20):
        self.width = width
        self.height = height
        self.columns = [random.randint(0, height) for _ in range(width)]
        self.chars = "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ01"
        
    def render(self, step: int) -> str:
        output = []
        for y in range(self.height):
            line = ""
            for x in range(self.width):
                if self.columns[x] > y:
                    distance = self.columns[x] - y
                    if distance == 1:
                        # Head of the column - bright white
                        char = random.choice(self.chars)
                        line += f"[bold white]{char}[/]"
                    elif distance < 5:
                        # Recent trail - bright green
                        char = random.choice(self.chars)
                        line += f"[green]{char}[/]"
                    elif distance < 10:
                        # Fading trail - dim green
                        char = random.choice(self.chars)
                        line += f"[dim green]{char}[/]"
                    else:
                        line += " "
                else:
                    line += " "
            output.append(line)
        
        # Update columns
        for x in range(self.width):
            if random.random() > 0.95:
                self.columns[x] = 0
            else:
                self.columns[x] += 1
                if self.columns[x] > self.height + 20:
                    self.columns[x] = 0
        
        return "\n".join(output)


class GlitchText:
    """Create glitch text effects."""
    
    @staticmethod
    def glitch(text: str, intensity: float = 0.1) -> Text:
        glitch_chars = "░▒▓█▄▌▐▀"
        result = Text()
        
        for char in text:
            if random.random() < intensity:
                # Glitch this character
                glitched = random.choice(glitch_chars)
                color = random.choice(["red", "green", "blue", "magenta", "cyan"])
                result.append(glitched, style=f"bold {color}")
            else:
                result.append(char, style="bold white")
        
        return result


class ParticleField:
    """Animated particle field effect."""
    
    def __init__(self, width: int = 80, height: int = 20, particles: int = 50):
        self.width = width
        self.height = height
        self.particles = []
        
        for _ in range(particles):
            self.particles.append({
                'x': random.uniform(0, width),
                'y': random.uniform(0, height),
                'vx': random.uniform(-0.5, 0.5),
                'vy': random.uniform(-0.3, 0.3),
                'char': random.choice('✦✧★☆·.'),
                'color': random.choice(['cyan', 'magenta', 'yellow', 'blue', 'green'])
            })
    
    def update(self):
        for p in self.particles:
            p['x'] += p['vx']
            p['y'] += p['vy']
            
            # Wrap around edges
            if p['x'] < 0:
                p['x'] = self.width
            elif p['x'] > self.width:
                p['x'] = 0
            
            if p['y'] < 0:
                p['y'] = self.height
            elif p['y'] > self.height:
                p['y'] = 0
    
    def render(self) -> str:
        # Create empty grid
        grid = [[' ' for _ in range(self.width)] for _ in range(self.height)]
        colors = [[None for _ in range(self.width)] for _ in range(self.height)]
        
        # Place particles
        for p in self.particles:
            x, y = int(p['x']), int(p['y'])
            if 0 <= x < self.width and 0 <= y < self.height:
                grid[y][x] = p['char']
                colors[y][x] = p['color']
        
        # Convert to string with colors
        lines = []
        for y in range(self.height):
            line = ""
            for x in range(self.width):
                if colors[y][x]:
                    line += f"[{colors[y][x]}]{grid[y][x]}[/]"
                else:
                    line += grid[y][x]
            lines.append(line)
        
        return "\n".join(lines)


class AsciiFireworks:
    """Animated ASCII fireworks display."""
    
    def __init__(self, width: int = 80, height: int = 30):
        self.width = width
        self.height = height
        self.fireworks = []
        self.explosions = []
    
    def launch(self):
        if random.random() > 0.9:
            self.fireworks.append({
                'x': random.randint(10, self.width - 10),
                'y': self.height - 1,
                'vy': -random.uniform(0.8, 1.2),
                'trail': [],
                'color': random.choice(['red', 'green', 'blue', 'yellow', 'magenta', 'cyan'])
            })
    
    def update(self):
        # Update fireworks
        for fw in self.fireworks[:]:
            fw['trail'].append((fw['x'], fw['y']))
            if len(fw['trail']) > 5:
                fw['trail'].pop(0)
            
            fw['y'] += fw['vy']
            fw['vy'] += 0.05  # Gravity
            
            if fw['vy'] > 0 and fw['y'] < self.height * 0.6:
                # Explode!
                self.explode(fw['x'], fw['y'], fw['color'])
                self.fireworks.remove(fw)
        
        # Update explosions
        for exp in self.explosions[:]:
            exp['age'] += 1
            if exp['age'] > exp['lifetime']:
                self.explosions.remove(exp)
    
    def explode(self, x: int, y: int, color: str):
        particles = []
        for _ in range(20):
            angle = random.uniform(0, 2 * math.pi)
            speed = random.uniform(0.5, 2)
            particles.append({
                'x': x,
                'y': y,
                'vx': math.cos(angle) * speed,
                'vy': math.sin(angle) * speed,
                'char': random.choice('*✦+·')
            })
        
        self.explosions.append({
            'particles': particles,
            'age': 0,
            'lifetime': 15,
            'color': color
        })
    
    def render(self) -> str:
        grid = [[' ' for _ in range(self.width)] for _ in range(self.height)]
        
        # Render firework trails
        for fw in self.fireworks:
            for i, (tx, ty) in enumerate(fw['trail']):
                if 0 <= int(tx) < self.width and 0 <= int(ty) < self.height:
                    intensity = i / len(fw['trail'])
                    char = '│' if intensity > 0.5 else '·'
                    grid[int(ty)][int(tx)] = f"[dim {fw['color']}]{char}[/]"
            
            # Render firework head
            if 0 <= int(fw['x']) < self.width and 0 <= int(fw['y']) < self.height:
                grid[int(fw['y'])][int(fw['x'])] = f"[bold {fw['color']}]▲[/]"
        
        # Render explosions
        for exp in self.explosions:
            fade = 1 - (exp['age'] / exp['lifetime'])
            for p in exp['particles']:
                p['x'] += p['vx']
                p['y'] += p['vy']
                p['vy'] += 0.1  # Gravity
                
                px, py = int(p['x']), int(p['y'])
                if 0 <= px < self.width and 0 <= py < self.height:
                    if fade > 0.5:
                        grid[py][px] = f"[bold {exp['color']}]{p['char']}[/]"
                    else:
                        grid[py][px] = f"[dim {exp['color']}]{p['char']}[/]"
        
        # Convert grid to string
        lines = []
        for row in grid:
            lines.append(''.join(row))
        
        return '\n'.join(lines)
