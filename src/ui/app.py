"""
Lock On - Main UI Application
Magnificent security monitoring interface
"""
if __package__ in {None, ""}:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parent))
    __package__ = "ui"
try:
    from .ctk import ctk
except ImportError:  # pragma: no cover - allow running as a script
    from ui.ctk import ctk  # type: ignore
from typing import Dict, Optional
import sys
import json
from pathlib import Path

# Import views
from .dashboard import DashboardView
from .monitor_view import MonitorView
from .permissions_view import PermissionsView
from .intelligence_view import IntelligenceView

# Import core
# Import core modules using absolute paths so the application can be
# executed from any entry point without relying on relative package
# structure. This avoids ``ImportError: attempted relative import beyond
# top-level package`` when ``src`` is added directly to ``sys.path``.
from core.monitor import FolderMonitor
from core.intelligence import IntelligenceEngine
from core.permissions import PermissionManager
from utils.config import Config
from utils.logger import SecurityLogger

# Set theme
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class LockOnApp:
    """Main Lock On application"""

    def __init__(self):
        """Initialize Lock On"""
        # Configuration
        self.config = Config()
        self.logger = SecurityLogger()

        # Core components
        self.monitor = FolderMonitor()
        self.intelligence = IntelligenceEngine()
        self.permissions = PermissionManager()

        # Create main window
        self.window = ctk.CTk()
        self.window.title("🔒 Lock On - Intelligent Folder Security")
        self.window.geometry("1400x900")
        self.window.minsize(1000, 700)

        # Window styling
        self.window.configure(fg_color="#0a0a0a")

        # Initialize UI
        self._setup_ui()
        self._bind_events()

        # Start monitoring
        self.monitor.start()

        # Load initial view
        self.switch_view("dashboard")

        self.logger.info("Lock On initialized successfully")

    def _setup_ui(self):
        """Setup the magnificent UI"""
        # Create main container with gradient effect
        self.main_container = ctk.CTkFrame(
            self.window,
            corner_radius=0,
            fg_color="#0a0a0a"
        )
        self.main_container.pack(fill="both", expand=True)

        # Create top bar
        self._create_top_bar()

        # Create content area
        self.content_frame = ctk.CTkFrame(
            self.main_container,
            corner_radius=0,
            fg_color="transparent"
        )
        self.content_frame.pack(fill="both", expand=True)

        # Configure grid
        self.content_frame.grid_columnconfigure(1, weight=1)
        self.content_frame.grid_rowconfigure(0, weight=1)

        # Create sidebar
        self._create_sidebar()

        # Create view container
        self.view_container = ctk.CTkFrame(
            self.content_frame,
            corner_radius=20,
            fg_color="#1a1a1a",
            border_width=1,
            border_color="#333333"
        )
        self.view_container.grid(row=0, column=1, sticky="nsew", padx=(0, 20), pady=20)

        # Initialize views
        self.views: Dict[str, ctk.CTkFrame] = {}
        self._init_views()

        # Create status bar
        self._create_status_bar()

    def _create_top_bar(self):
        """Create futuristic top bar"""
        self.top_bar = ctk.CTkFrame(
            self.main_container,
            height=60,
            corner_radius=0,
            fg_color="#0f0f0f",
            border_width=0
        )
        self.top_bar.pack(fill="x")
        self.top_bar.pack_propagate(False)

        # Logo and title
        title_frame = ctk.CTkFrame(self.top_bar, fg_color="transparent")
        title_frame.pack(side="left", padx=20)

        # Animated lock icon
        self.lock_icon = ctk.CTkLabel(
            title_frame,
            text="🔒",
            font=ctk.CTkFont(size=28)
        )
        self.lock_icon.pack(side="left", padx=(0, 10))

        # Title with glow effect
        self.title_label = ctk.CTkLabel(
            title_frame,
            text="LOCK ON",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color="#00ff88"
        )
        self.title_label.pack(side="left")

        # Status indicator
        self.status_frame = ctk.CTkFrame(
            title_frame,
            fg_color="transparent"
        )
        self.status_frame.pack(side="left", padx=20)

        self.status_dot = ctk.CTkLabel(
            self.status_frame,
            text="●",
            font=ctk.CTkFont(size=12),
            text_color="#00ff00"
        )
        self.status_dot.pack(side="left", padx=(0, 5))

        self.status_text = ctk.CTkLabel(
            self.status_frame,
            text="ACTIVE",
            font=ctk.CTkFont(size=12),
            text_color="#888888"
        )
        self.status_text.pack(side="left")

        # Right side controls
        controls_frame = ctk.CTkFrame(self.top_bar, fg_color="transparent")
        controls_frame.pack(side="right", padx=20)

        # Emergency shutdown button
        self.emergency_btn = ctk.CTkButton(
            controls_frame,
            text="⚠️ EMERGENCY",
            width=120,
            height=32,
            fg_color="#ff3333",
            hover_color="#cc0000",
            command=self.emergency_shutdown
        )
        self.emergency_btn.pack(side="right", padx=(10, 0))

        # Shield toggle
        self.shield_btn = ctk.CTkButton(
            controls_frame,
            text="🛡️ Shield: ON",
            width=120,
            height=32,
            fg_color="#0066ff",
            hover_color="#0052cc",
            command=self.toggle_shield
        )
        self.shield_btn.pack(side="right")

    def _create_sidebar(self):
        """Create modern sidebar navigation"""
        self.sidebar = ctk.CTkFrame(
            self.content_frame,
            width=250,
            corner_radius=20,
            fg_color="#151515",
            border_width=1,
            border_color="#333333"
        )
        self.sidebar.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        self.sidebar.grid_propagate(False)

        # Navigation buttons
        self.nav_buttons = {}

        nav_items = [
            ("dashboard", "📊", "Dashboard", "Overview of system security"),
            ("monitor", "👁️", "Monitor", "Real-time folder monitoring"),
            ("permissions", "🔐", "Permissions", "Manage access rules"),
            ("intelligence", "🧠", "Intelligence", "AI pattern configuration")
        ]

        for idx, (view_name, icon, label, description) in enumerate(nav_items):
            btn_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
            btn_frame.pack(fill="x", pady=(20 if idx == 0 else 5, 5), padx=15)

            btn = ctk.CTkButton(
                btn_frame,
                text=f"{icon}  {label}",
                anchor="w",
                height=50,
                fg_color="transparent",
                hover_color="#2a2a2a",
                font=ctk.CTkFont(size=16),
                command=lambda v=view_name: self.switch_view(v)
            )
            btn.pack(fill="x")

            # Description label
            desc = ctk.CTkLabel(
                btn_frame,
                text=description,
                font=ctk.CTkFont(size=11),
                text_color="#666666",
                anchor="w"
            )
            desc.pack(fill="x", padx=(50, 0))

            self.nav_buttons[view_name] = btn

        # Spacer
        spacer = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        spacer.pack(fill="both", expand=True)

        # Folder selector at bottom
        folder_frame = ctk.CTkFrame(
            self.sidebar,
            fg_color="#222222",
            corner_radius=10
        )
        folder_frame.pack(fill="x", padx=15, pady=15)

        folder_label = ctk.CTkLabel(
            folder_frame,
            text="🔒 Locked Folder:",
            font=ctk.CTkFont(size=12),
            text_color="#888888"
        )
        folder_label.pack(anchor="w", padx=10, pady=(10, 5))

        self.folder_path = ctk.CTkLabel(
            folder_frame,
            text="No folder selected",
            font=ctk.CTkFont(size=11),
            text_color="#00ff88",
            wraplength=200,
            anchor="w"
        )
        self.folder_path.pack(anchor="w", padx=10, pady=(0, 5))

        self.select_folder_btn = ctk.CTkButton(
            folder_frame,
            text="Select Folder",
            height=28,
            command=self.select_folder
        )
        self.select_folder_btn.pack(fill="x", padx=10, pady=(5, 10))

    def _create_status_bar(self):
        """Create status bar"""
        self.status_bar = ctk.CTkFrame(
            self.main_container,
            height=30,
            corner_radius=0,
            fg_color="#0f0f0f"
        )
        self.status_bar.pack(fill="x", side="bottom")
        self.status_bar.pack_propagate(False)

        # Status message
        self.status_message = ctk.CTkLabel(
            self.status_bar,
            text="System ready",
            font=ctk.CTkFont(size=12),
            text_color="#888888"
        )
        self.status_message.pack(side="left", padx=20)

        # Activity indicators
        activity_frame = ctk.CTkFrame(self.status_bar, fg_color="transparent")
        activity_frame.pack(side="right", padx=20)

        # File count
        self.file_count = ctk.CTkLabel(
            activity_frame,
            text="📁 0 files",
            font=ctk.CTkFont(size=12)
        )
        self.file_count.pack(side="left", padx=10)

        # Threat level
        self.threat_level = ctk.CTkLabel(
            activity_frame,
            text="⚡ Threat: LOW",
            font=ctk.CTkFont(size=12),
            text_color="#00ff00"
        )
        self.threat_level.pack(side="left", padx=10)

    def _init_views(self):
        """Initialize all views"""
        self.views["dashboard"] = DashboardView(self.view_container, self)
        self.views["monitor"] = MonitorView(self.view_container, self)
        self.views["permissions"] = PermissionsView(self.view_container, self)
        self.views["intelligence"] = IntelligenceView(self.view_container, self)

        # Hide all views initially
        for view in self.views.values():
            view.pack_forget()

    def _bind_events(self):
        """Bind application events"""
        self.window.protocol("WM_DELETE_WINDOW", self._on_closing)

        # Keyboard shortcuts
        self.window.bind("<Control-q>", lambda e: self._on_closing())
        self.window.bind("<F1>", lambda e: self.switch_view("dashboard"))
        self.window.bind("<F2>", lambda e: self.switch_view("monitor"))
        self.window.bind("<F3>", lambda e: self.switch_view("permissions"))
        self.window.bind("<F4>", lambda e: self.switch_view("intelligence"))
        self.window.bind("<Control-e>", lambda e: self.emergency_shutdown())

    def switch_view(self, view_name: str):
        """Switch between views"""
        # Hide all views
        for view in self.views.values():
            view.pack_forget()

        # Show selected view
        if view_name in self.views:
            self.views[view_name].pack(fill="both", expand=True, padx=20, pady=20)

            # Update navigation buttons
            for name, btn in self.nav_buttons.items():
                if name == view_name:
                    btn.configure(fg_color="#0066ff")
                else:
                    btn.configure(fg_color="transparent")

            self.status_message.configure(text=f"Viewing: {view_name.title()}")

    def select_folder(self):
        """Select folder to monitor"""
        from tkinter import filedialog

        folder = filedialog.askdirectory(
            title="Select Folder to Lock On"
        )

        if folder:
            self.monitor.set_target_folder(folder)
            self.folder_path.configure(text=folder)
            self.status_message.configure(text=f"Locked on: {folder}")
            self.logger.info(f"Locked on folder: {folder}")

    def toggle_shield(self):
        """Toggle active protection"""
        if self.monitor.shield_active:
            self.monitor.deactivate_shield()
            self.shield_btn.configure(
                text="🛡️ Shield: OFF",
                fg_color="#666666"
            )
        else:
            self.monitor.activate_shield()
            self.shield_btn.configure(
                text="🛡️ Shield: ON",
                fg_color="#0066ff"
            )

    def emergency_shutdown(self):
        """Emergency shutdown all monitoring"""
        from tkinter import messagebox

        if messagebox.askyesno("Emergency Shutdown", 
                               "This will stop all monitoring and protection. Continue?"):
            self.monitor.emergency_stop()
            self.status_dot.configure(text_color="#ff0000")
            self.status_text.configure(text="STOPPED")
            self.logger.critical("Emergency shutdown activated")

    def _on_closing(self):
        """Handle window closing"""
        self.monitor.stop()
        self.window.destroy()
        sys.exit(0)

    def run(self):
        """Start the application"""
        self.window.mainloop()
