"""
Monitor View - Real-time file system monitoring interface
"""
import customtkinter as ctk
from datetime import datetime
import threading
from pathlib import Path


class MonitorView(ctk.CTkFrame):
    """Real-time monitoring view"""

    def __init__(self, parent, app):
        super().__init__(parent, corner_radius=0, fg_color="transparent")
        self.app = app
        self.file_events = []

        self._create_layout()

    def _create_layout(self):
        """Create monitor layout"""
        # Title
        title = ctk.CTkLabel(
            self,
            text="Real-Time Monitor",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        title.pack(pady=(0, 20))

        # Control panel
        self._create_control_panel()

        # Main content area
        content_frame = ctk.CTkFrame(self, fg_color="transparent")
        content_frame.pack(fill="both", expand=True, pady=20)

        # Configure grid
        content_frame.grid_columnconfigure(0, weight=1)
        content_frame.grid_columnconfigure(1, weight=2)
        content_frame.grid_rowconfigure(0, weight=1)

        # File tree
        self._create_file_tree(content_frame)

        # Activity log
        self._create_activity_log(content_frame)

    def _create_control_panel(self):
        """Create monitor controls"""
        control_frame = ctk.CTkFrame(self, corner_radius=15, fg_color="#2a2a2a")
        control_frame.pack(fill="x", pady=10)

        # Monitoring status
        self.status_label = ctk.CTkLabel(
            control_frame,
            text="⚡ Monitoring: ACTIVE",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#00ff00"
        )
        self.status_label.pack(side="left", padx=20, pady=15)

        # Filter controls
        filter_frame = ctk.CTkFrame(control_frame, fg_color="transparent")
        filter_frame.pack(side="left", padx=20)

        ctk.CTkLabel(
            filter_frame,
            text="Filter:",
            font=ctk.CTkFont(size=14)
        ).pack(side="left", padx=(0, 10))

        self.filter_var = ctk.StringVar(value="all")
        filter_menu = ctk.CTkOptionMenu(
            filter_frame,
            values=["All Events", "High Risk", "Medium Risk", "Low Risk", "File Created", "File Modified", "File Deleted"],
            variable=self.filter_var,
            width=150,
            command=self._apply_filter
        )
        filter_menu.pack(side="left")

        # Action buttons
        button_frame = ctk.CTkFrame(control_frame, fg_color="transparent")
        button_frame.pack(side="right", padx=20)

        self.pause_btn = ctk.CTkButton(
            button_frame,
            text="⏸️ Pause",
            width=100,
            command=self._toggle_monitoring
        )
        self.pause_btn.pack(side="left", padx=5)

        clear_btn = ctk.CTkButton(
            button_frame,
            text="🗑️ Clear Log",
            width=100,
            command=self._clear_log
        )
        clear_btn.pack(side="left", padx=5)

    def _create_file_tree(self, parent):
        """Create file tree view"""
        tree_frame = ctk.CTkFrame(parent, corner_radius=15, fg_color="#2a2a2a")
        tree_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        title = ctk.CTkLabel(
            tree_frame,
            text="📁 Monitored Files",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        title.pack(pady=(15, 10))

        # Tree view (simplified)
        self.tree_text = ctk.CTkTextbox(
            tree_frame,
            font=ctk.CTkFont(family="monospace", size=12),
            width=300
        )
        self.tree_text.pack(fill="both", expand=True, padx=15, pady=(0, 15))

        # Sample tree structure
        tree_content = """📁 Protected Folder
├── 📁 Documents
│   ├── 📄 report.pdf
│   └── 📄 notes.txt
├── 📁 Images
│   ├── 🖼️ photo1.jpg
│   └── 🖼️ photo2.png
└── 📁 Projects
    └── 🐍 script.py"""

        self.tree_text.insert("1.0", tree_content)
        self.tree_text.configure(state="disabled")

    def _create_activity_log(self, parent):
        """Create activity log"""
        log_frame = ctk.CTkFrame(parent, corner_radius=15, fg_color="#2a2a2a")
        log_frame.grid(row=0, column=1, sticky="nsew")

        title = ctk.CTkLabel(
            log_frame,
            text="📋 Activity Log",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        title.pack(pady=(15, 10))

        # Log display
        self.log_text = ctk.CTkTextbox(
            log_frame,
            font=ctk.CTkFont(family="monospace", size=11),
            wrap="none"
        )
        self.log_text.pack(fill="both", expand=True, padx=15, pady=(0, 15))

        # Configure tags for colored text
        self.log_text.tag_config("high_risk", foreground="#ff0000")
        self.log_text.tag_config("medium_risk", foreground="#ff9900")
        self.log_text.tag_config("low_risk", foreground="#00ff00")
        self.log_text.tag_config("info", foreground="#0099ff")

        # Initial log
        self.add_log_entry("Monitor initialized", "info")

    def add_log_entry(self, message: str, level: str = "info"):
        """Add entry to activity log"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        # Icons for different levels
        icons = {
            "high_risk": "🔴",
            "medium_risk": "🟡",
            "low_risk": "🟢",
            "info": "ℹ️"
        }

        icon = icons.get(level, "•")
        entry = f"[{timestamp}] {icon} {message}\n"

        # Add to log
        self.log_text.configure(state="normal")
        self.log_text.insert("end", entry, level)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

        # Store event
        self.file_events.append({
            'timestamp': datetime.now(),
            'message': message,
            'level': level
        })

    def _toggle_monitoring(self):
        """Toggle monitoring pause/resume"""
        if self.pause_btn.cget("text") == "⏸️ Pause":
            self.pause_btn.configure(text="▶️ Resume")
            self.status_label.configure(
                text="⏸️ Monitoring: PAUSED",
                text_color="#ff9900"
            )
            # Pause monitoring logic
        else:
            self.pause_btn.configure(text="⏸️ Pause")
            self.status_label.configure(
                text="⚡ Monitoring: ACTIVE",
                text_color="#00ff00"
            )
            # Resume monitoring logic

    def _clear_log(self):
        """Clear activity log"""
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")
        self.file_events.clear()
        self.add_log_entry("Log cleared", "info")

    def _apply_filter(self, choice: str):
        """Apply log filter"""
        # Filter implementation
        self.add_log_entry(f"Filter applied: {choice}", "info")
