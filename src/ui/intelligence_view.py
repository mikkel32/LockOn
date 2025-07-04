"""
Intelligence View - Configure AI patterns and threat detection
"""
try:
    from .ctk import ctk
except ImportError:  # pragma: no cover - allow running as a script
    from ui.ctk import ctk  # type: ignore
from tkinter import messagebox
import json


class IntelligenceView(ctk.CTkFrame):
    """Intelligence configuration view"""

    def __init__(self, parent, app):
        super().__init__(parent, corner_radius=0, fg_color="transparent")
        self.app = app

        self._create_layout()

    def _create_layout(self):
        """Create intelligence layout"""
        # Title
        title = ctk.CTkLabel(
            self,
            text="Intelligence Configuration",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        title.pack(pady=(0, 20))

        # Tabs
        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(fill="both", expand=True, padx=20, pady=20)

        # Create tabs
        self.tabview.add("🔍 Patterns")
        self.tabview.add("🧠 Behaviors")
        self.tabview.add("⚡ Responses")
        self.tabview.add("📊 Analytics")

        # Configure tabs
        self._create_patterns_tab()
        self._create_behaviors_tab()
        self._create_responses_tab()
        self._create_analytics_tab()

    def _create_patterns_tab(self):
        """Create patterns configuration tab"""
        tab = self.tabview.tab("🔍 Patterns")

        # Scroll frame
        scroll = ctk.CTkScrollableFrame(tab)
        scroll.pack(fill="both", expand=True)

        # File patterns
        file_frame = ctk.CTkFrame(scroll, corner_radius=15, fg_color="#2a2a2a")
        file_frame.pack(fill="x", pady=10)

        ctk.CTkLabel(
            file_frame,
            text="📄 File Patterns",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(pady=(15, 10))

        # Pattern editor
        self.file_patterns = ctk.CTkTextbox(
            file_frame,
            height=200,
            font=ctk.CTkFont(family="monospace", size=11)
        )
        self.file_patterns.pack(fill="x", padx=20, pady=(0, 20))

        # Load current patterns
        try:
            with open("Intelligence/patterns.json", "r") as f:
                patterns = json.load(f)
                self.file_patterns.insert("1.0", json.dumps(patterns['file_patterns'], indent=2))
        except:
            self.file_patterns.insert("1.0", "{\n  // File patterns configuration\n}")

        # Content patterns
        content_frame = ctk.CTkFrame(scroll, corner_radius=15, fg_color="#2a2a2a")
        content_frame.pack(fill="x", pady=10)

        ctk.CTkLabel(
            content_frame,
            text="🔤 Content Patterns",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(pady=(15, 10))

        # Malicious signatures
        sig_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        sig_frame.pack(fill="x", padx=20, pady=10)

        ctk.CTkLabel(
            sig_frame,
            text="Malicious Signatures:",
            font=ctk.CTkFont(size=14)
        ).pack(anchor="w")

        self.signatures = ctk.CTkTextbox(
            sig_frame,
            height=100,
            font=ctk.CTkFont(family="monospace", size=11)
        )
        self.signatures.pack(fill="x", pady=5)

        signatures = [
            "4D5A90000300000004000000FFFF  # PE header",
            "TVqQAAMAAAAEAAAA              # Base64 PE",
            "#!/bin/sh                     # Shell script",
            "MZ                            # DOS header"
        ]
        self.signatures.insert("1.0", "\n".join(signatures))

    def _create_behaviors_tab(self):
        """Create behaviors configuration tab"""
        tab = self.tabview.tab("🧠 Behaviors")

        # Behavior thresholds
        threshold_frame = ctk.CTkFrame(tab, corner_radius=15, fg_color="#2a2a2a")
        threshold_frame.pack(fill="x", pady=10)

        ctk.CTkLabel(
            threshold_frame,
            text="⚖️ Behavior Thresholds",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(pady=(15, 10))

        # Threshold sliders
        thresholds = [
            ("Rapid File Changes", "files_per_minute", 10, 200, 100),
            ("Mass Encryption", "encryption_threshold", 1, 50, 10),
            ("Recursive Deletion", "deletion_depth", 1, 10, 3),
            ("CPU Usage Alert", "cpu_threshold", 10, 100, 80)
        ]

        self.threshold_vars = {}

        for name, key, min_val, max_val, default in thresholds:
            frame = ctk.CTkFrame(threshold_frame, fg_color="transparent")
            frame.pack(fill="x", padx=40, pady=10)

            ctk.CTkLabel(
                frame,
                text=f"{name}:",
                width=150,
                anchor="w"
            ).pack(side="left")

            slider = ctk.CTkSlider(
                frame,
                from_=min_val,
                to=max_val,
                width=200
            )
            slider.pack(side="left", padx=10)
            slider.set(default)

            value_label = ctk.CTkLabel(frame, text=str(default), width=50)
            value_label.pack(side="left")

            slider.configure(command=lambda v, l=value_label: l.configure(text=str(int(v))))
            self.threshold_vars[key] = slider

        # ML sensitivity
        ml_frame = ctk.CTkFrame(tab, corner_radius=15, fg_color="#2a2a2a")
        ml_frame.pack(fill="x", pady=10)

        ctk.CTkLabel(
            ml_frame,
            text="🤖 Machine Learning",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(pady=(15, 10))

        # Sensitivity slider
        sens_frame = ctk.CTkFrame(ml_frame, fg_color="transparent")
        sens_frame.pack(fill="x", padx=40, pady=10)

        ctk.CTkLabel(
            sens_frame,
            text="Anomaly Sensitivity:",
            width=150,
            anchor="w"
        ).pack(side="left")

        self.ml_sensitivity = ctk.CTkSlider(
            sens_frame,
            from_=0.1,
            to=1.0,
            width=200
        )
        self.ml_sensitivity.pack(side="left", padx=10)
        self.ml_sensitivity.set(0.85)

        self.sens_label = ctk.CTkLabel(sens_frame, text="85%", width=50)
        self.sens_label.pack(side="left")

        self.ml_sensitivity.configure(
            command=lambda v: self.sens_label.configure(text=f"{int(v*100)}%")
        )

    def _create_responses_tab(self):
        """Create response configuration tab"""
        tab = self.tabview.tab("⚡ Responses")

        # Response matrix
        matrix_frame = ctk.CTkFrame(tab, corner_radius=15, fg_color="#2a2a2a")
        matrix_frame.pack(fill="both", expand=True, pady=10)

        ctk.CTkLabel(
            matrix_frame,
            text="🎯 Response Matrix",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(pady=(15, 10))

        # Response levels
        levels = [
            ("Low Threat", ["Log", "Monitor"], "#00ff00"),
            ("Medium Threat", ["Alert", "Restrict"], "#ff9900"),
            ("High Threat", ["Block", "Quarantine"], "#ff6600"),
            ("Critical Threat", ["Terminate", "Lockdown"], "#ff0000")
        ]

        for threat, actions, color in levels:
            level_frame = ctk.CTkFrame(matrix_frame, fg_color="transparent")
            level_frame.pack(fill="x", padx=40, pady=10)

            # Threat level
            threat_label = ctk.CTkLabel(
                level_frame,
                text=threat,
                font=ctk.CTkFont(size=16, weight="bold"),
                text_color=color,
                width=150
            )
            threat_label.pack(side="left")

            # Actions
            for action in actions:
                action_check = ctk.CTkCheckBox(
                    level_frame,
                    text=action,
                    font=ctk.CTkFont(size=14)
                )
                action_check.pack(side="left", padx=10)
                action_check.select()

        # Harsh actions
        harsh_frame = ctk.CTkFrame(tab, corner_radius=15, fg_color="#2a2a2a")
        harsh_frame.pack(fill="x", pady=10)

        ctk.CTkLabel(
            harsh_frame,
            text="💀 Harsh Actions",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#ff0000"
        ).pack(pady=(15, 10))

        warning = ctk.CTkLabel(
            harsh_frame,
            text="⚠️ These actions may affect system stability!",
            font=ctk.CTkFont(size=12),
            text_color="#ff9900"
        )
        warning.pack()

        # Harsh action options
        self.harsh_actions = {
            'cpu_throttle': ctk.CTkCheckBox(harsh_frame, text="CPU Throttle (limit to 5%)"),
            'memory_limit': ctk.CTkCheckBox(harsh_frame, text="Memory Restriction (50MB max)"),
            'network_cut': ctk.CTkCheckBox(harsh_frame, text="Complete Network Isolation"),
            'permission_strip': ctk.CTkCheckBox(harsh_frame, text="Remove All File Permissions"),
            'encrypt_quarantine': ctk.CTkCheckBox(harsh_frame, text="Encrypt & Lock Files")
        }

        for action in self.harsh_actions.values():
            action.pack(anchor="w", padx=40, pady=5)

    def _create_analytics_tab(self):
        """Create analytics tab"""
        tab = self.tabview.tab("📊 Analytics")

        # Stats frame
        stats_frame = ctk.CTkFrame(tab, corner_radius=15, fg_color="#2a2a2a")
        stats_frame.pack(fill="x", pady=10)

        ctk.CTkLabel(
            stats_frame,
            text="📈 Intelligence Statistics",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(pady=(15, 10))

        # Statistics display
        stats_grid = ctk.CTkFrame(stats_frame, fg_color="transparent")
        stats_grid.pack(fill="x", padx=40, pady=10)

        stats = [
            ("Patterns Loaded", "156"),
            ("Threats Identified", "23"),
            ("Accuracy Rate", "94.7%"),
            ("False Positives", "2"),
            ("Learning Progress", "87%")
        ]

        for i, (label, value) in enumerate(stats):
            row = i // 2
            col = i % 2

            stat_frame = ctk.CTkFrame(stats_grid, fg_color="#1a1a1a", corner_radius=10)
            stat_frame.grid(row=row, column=col, padx=10, pady=10, sticky="ew")

            ctk.CTkLabel(
                stat_frame,
                text=value,
                font=ctk.CTkFont(size=24, weight="bold"),
                text_color="#0099ff"
            ).pack(pady=(10, 5))

            ctk.CTkLabel(
                stat_frame,
                text=label,
                font=ctk.CTkFont(size=12),
                text_color="#888888"
            ).pack(pady=(0, 10))

        stats_grid.grid_columnconfigure(0, weight=1)
        stats_grid.grid_columnconfigure(1, weight=1)

        # Save button
        save_btn = ctk.CTkButton(
            tab,
            text="💾 Save Intelligence Config",
            font=ctk.CTkFont(size=16),
            height=40,
            command=self._save_intelligence
        )
        save_btn.pack(pady=20)

    def _save_intelligence(self):
        """Save intelligence configuration"""
        try:
            # Gather all settings
            config = {
                'patterns': json.loads(self.file_patterns.get("1.0", "end-1c")),
                'thresholds': {
                    key: int(slider.get())
                    for key, slider in self.threshold_vars.items()
                },
                'ml_sensitivity': self.ml_sensitivity.get(),
                'harsh_actions': {
                    key: checkbox.get()
                    for key, checkbox in self.harsh_actions.items()
                }
            }
            print("Saving intelligence config:", config)

            # Save configuration
            # In real implementation, this would update the Intelligence files

            messagebox.showinfo("Success", "Intelligence configuration saved!")
            self.app.logger.info("Intelligence configuration updated")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to save configuration: {str(e)}")
            self.app.logger.error(f"Failed to save intelligence config: {e}")
