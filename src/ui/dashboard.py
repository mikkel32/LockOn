"""
Dashboard View - Main overview of system security status
"""
from .ctk import ctk
from datetime import datetime
import threading
from typing import Dict, List


class DashboardView(ctk.CTkFrame):
    """Main dashboard showing security overview"""

    def __init__(self, parent, app):
        super().__init__(parent, corner_radius=0, fg_color="transparent")
        self.app = app

        # Create layout
        self._create_layout()

        # Start update thread
        self.update_thread = threading.Thread(target=self._update_stats, daemon=True)
        self.update_thread.start()

    def _create_layout(self):
        """Create dashboard layout"""
        # Main container
        main_container = ctk.CTkScrollableFrame(self)
        main_container.pack(fill="both", expand=True)

        # Title
        title = ctk.CTkLabel(
            main_container,
            text="Security Dashboard",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        title.pack(pady=(0, 20))

        # Stats grid
        stats_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        stats_frame.pack(fill="x", pady=20)

        # Configure grid
        for i in range(4):
            stats_frame.grid_columnconfigure(i, weight=1)

        # Create stat cards
        self._create_stat_card(stats_frame, "🛡️", "Protection Status", "ACTIVE", "#00ff00", 0, 0)
        self._create_stat_card(stats_frame, "📁", "Files Monitored", "0", "#0099ff", 0, 1)
        self._create_stat_card(stats_frame, "⚠️", "Threats Detected", "0", "#ff9900", 0, 2)
        self._create_stat_card(stats_frame, "🔒", "Actions Taken", "0", "#ff0066", 0, 3)

        # Threat meter
        self._create_threat_meter(main_container)

        # Activity graph
        self._create_activity_graph(main_container)

        # Recent events
        self._create_recent_events(main_container)

    def _create_stat_card(self, parent, icon: str, label: str, value: str, color: str, row: int, col: int):
        """Create a statistics card"""
        card = ctk.CTkFrame(
            parent,
            corner_radius=15,
            fg_color="#2a2a2a",
            border_width=2,
            border_color=color
        )
        card.grid(row=row, column=col, padx=10, pady=10, sticky="nsew")

        # Icon
        icon_label = ctk.CTkLabel(
            card,
            text=icon,
            font=ctk.CTkFont(size=40)
        )
        icon_label.pack(pady=(20, 10))

        # Value
        value_label = ctk.CTkLabel(
            card,
            text=value,
            font=ctk.CTkFont(size=32, weight="bold"),
            text_color=color
        )
        value_label.pack()

        # Label
        label_text = ctk.CTkLabel(
            card,
            text=label,
            font=ctk.CTkFont(size=14),
            text_color="#888888"
        )
        label_text.pack(pady=(5, 20))

        # Store reference for updates
        setattr(self, f"{label.lower().replace(' ', '_')}_value", value_label)

    def _create_threat_meter(self, parent):
        """Create threat level meter"""
        meter_frame = ctk.CTkFrame(parent, corner_radius=15, fg_color="#2a2a2a")
        meter_frame.pack(fill="x", pady=20)

        title = ctk.CTkLabel(
            meter_frame,
            text="🎯 Current Threat Level",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        title.pack(pady=(20, 10))

        # Threat level bar
        self.threat_progress = ctk.CTkProgressBar(
            meter_frame,
            width=400,
            height=30,
            corner_radius=15
        )
        self.threat_progress.pack(pady=10)
        self.threat_progress.set(0.2)  # Low threat

        # Threat level text
        self.threat_text = ctk.CTkLabel(
            meter_frame,
            text="LOW",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color="#00ff00"
        )
        self.threat_text.pack(pady=(5, 20))

    def _create_activity_graph(self, parent):
        """Create activity visualization"""
        graph_frame = ctk.CTkFrame(parent, corner_radius=15, fg_color="#2a2a2a")
        graph_frame.pack(fill="both", expand=True, pady=20)

        title = ctk.CTkLabel(
            graph_frame,
            text="📊 File Activity (Last 24 Hours)",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        title.pack(pady=(20, 10))

        # Placeholder for graph
        canvas = ctk.CTkCanvas(
            graph_frame,
            width=600,
            height=200,
            bg="#1a1a1a",
            highlightthickness=0
        )
        canvas.pack(pady=20)

        # Draw simple activity bars
        for i in range(24):
            height = 50 + (i * 3) % 100
            x = 25 + i * 24
            canvas.create_rectangle(
                x, 200-height, x+20, 200,
                fill="#0099ff",
                outline=""
            )

    def _create_recent_events(self, parent):
        """Create recent events list"""
        events_frame = ctk.CTkFrame(parent, corner_radius=15, fg_color="#2a2a2a")
        events_frame.pack(fill="both", expand=True, pady=20)

        title = ctk.CTkLabel(
            events_frame,
            text="📋 Recent Security Events",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        title.pack(pady=(20, 10))

        # Events list
        self.events_text = ctk.CTkTextbox(
            events_frame,
            width=600,
            height=200,
            font=ctk.CTkFont(family="monospace", size=12)
        )
        self.events_text.pack(padx=20, pady=(10, 20), fill="both", expand=True)

        # Sample events
        sample_events = [
            f"{datetime.now().strftime('%H:%M:%S')} - System initialized",
            f"{datetime.now().strftime('%H:%M:%S')} - Shield activated",
            f"{datetime.now().strftime('%H:%M:%S')} - Monitoring started"
        ]

        for event in sample_events:
            self.events_text.insert("end", event + "\n")

        self.events_text.configure(state="disabled")

    def _update_stats(self):
        """Update dashboard statistics"""
        import time
        while True:
            try:
                if hasattr(self.app, 'monitor') and self.app.monitor.stats:
                    stats = self.app.monitor.stats

                    # Update values
                    if hasattr(self, 'files_monitored_value'):
                        self.files_monitored_value.configure(
                            text=str(stats.get('files_monitored', 0))
                        )
                    if hasattr(self, 'threats_detected_value'):
                        self.threats_detected_value.configure(
                            text=str(stats.get('threats_detected', 0))
                        )
                    if hasattr(self, 'actions_taken_value'):
                        self.actions_taken_value.configure(
                            text=str(stats.get('actions_taken', 0))
                        )

            except:
                pass

            time.sleep(1)
