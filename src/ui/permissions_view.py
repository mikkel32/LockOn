"""
Permissions View - Manage access rules and security policies
"""
import customtkinter as ctk
from tkinter import messagebox
import json


class PermissionsView(ctk.CTkFrame):
    """Permissions management view"""

    def __init__(self, parent, app):
        super().__init__(parent, corner_radius=0, fg_color="transparent")
        self.app = app

        self._create_layout()

    def _create_layout(self):
        """Create permissions layout"""
        # Title
        title = ctk.CTkLabel(
            self,
            text="Access Permissions",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        title.pack(pady=(0, 20))

        # Main container
        main_container = ctk.CTkScrollableFrame(self)
        main_container.pack(fill="both", expand=True)

        # Security level selector
        self._create_security_level(main_container)

        # File permissions
        self._create_file_permissions(main_container)

        # Process permissions
        self._create_process_permissions(main_container)

        # Network permissions
        self._create_network_permissions(main_container)

        # Custom rules
        self._create_custom_rules(main_container)

    def _create_security_level(self, parent):
        """Create security level selector"""
        level_frame = ctk.CTkFrame(parent, corner_radius=15, fg_color="#2a2a2a")
        level_frame.pack(fill="x", pady=20)

        title = ctk.CTkLabel(
            level_frame,
            text="🛡️ Security Level",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        title.pack(pady=(20, 10))

        # Level options
        levels = [
            ("Passive", "Monitor and log only", "#00ff00"),
            ("Active", "Block suspicious activities", "#0099ff"),
            ("Aggressive", "Terminate threats immediately", "#ff9900"),
            ("Paranoid", "Maximum security", "#ff0000")
        ]

        self.security_level = ctk.StringVar(value="Active")

        for level, desc, color in levels:
            frame = ctk.CTkFrame(level_frame, fg_color="transparent")
            frame.pack(fill="x", padx=40, pady=5)

            radio = ctk.CTkRadioButton(
                frame,
                text=level,
                variable=self.security_level,
                value=level,
                font=ctk.CTkFont(size=16, weight="bold"),
                text_color=color,
                command=self._update_security_level
            )
            radio.pack(side="left")

            desc_label = ctk.CTkLabel(
                frame,
                text=f"- {desc}",
                font=ctk.CTkFont(size=12),
                text_color="#888888"
            )
            desc_label.pack(side="left", padx=(20, 0))

    def _create_file_permissions(self, parent):
        """Create file permissions section"""
        file_frame = ctk.CTkFrame(parent, corner_radius=15, fg_color="#2a2a2a")
        file_frame.pack(fill="x", pady=20)

        title = ctk.CTkLabel(
            file_frame,
            text="📁 File Permissions",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        title.pack(pady=(20, 10))

        # Allowed extensions
        ext_frame = ctk.CTkFrame(file_frame, fg_color="transparent")
        ext_frame.pack(fill="x", padx=40, pady=10)

        ctk.CTkLabel(
            ext_frame,
            text="Allowed Extensions:",
            font=ctk.CTkFont(size=14)
        ).pack(anchor="w")

        self.allowed_ext = ctk.CTkTextbox(
            ext_frame,
            height=60,
            font=ctk.CTkFont(size=12)
        )
        self.allowed_ext.pack(fill="x", pady=5)
        self.allowed_ext.insert("1.0", ".txt, .doc, .pdf, .jpg, .png, .mp3, .mp4")

        # Blocked extensions
        ctk.CTkLabel(
            ext_frame,
            text="Blocked Extensions:",
            font=ctk.CTkFont(size=14)
        ).pack(anchor="w", pady=(10, 0))

        self.blocked_ext = ctk.CTkTextbox(
            ext_frame,
            height=60,
            font=ctk.CTkFont(size=12)
        )
        self.blocked_ext.pack(fill="x", pady=5)
        self.blocked_ext.insert("1.0", ".exe, .dll, .bat, .cmd, .scr, .vbs")

        # Options
        self.protect_system = ctk.CTkCheckBox(
            file_frame,
            text="Protect system files",
            font=ctk.CTkFont(size=14)
        )
        self.protect_system.pack(anchor="w", padx=40, pady=5)
        self.protect_system.select()

        self.backup_delete = ctk.CTkCheckBox(
            file_frame,
            text="Backup before delete",
            font=ctk.CTkFont(size=14)
        )
        self.backup_delete.pack(anchor="w", padx=40, pady=(0, 20))
        self.backup_delete.select()

    def _create_process_permissions(self, parent):
        """Create process permissions section"""
        process_frame = ctk.CTkFrame(parent, corner_radius=15, fg_color="#2a2a2a")
        process_frame.pack(fill="x", pady=20)

        title = ctk.CTkLabel(
            process_frame,
            text="⚙️ Process Permissions",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        title.pack(pady=(20, 10))

        # Whitelisted processes
        white_frame = ctk.CTkFrame(process_frame, fg_color="transparent")
        white_frame.pack(fill="x", padx=40, pady=10)

        ctk.CTkLabel(
            white_frame,
            text="Whitelisted Processes:",
            font=ctk.CTkFont(size=14)
        ).pack(anchor="w")

        self.whitelist_proc = ctk.CTkTextbox(
            white_frame,
            height=80,
            font=ctk.CTkFont(size=12)
        )
        self.whitelist_proc.pack(fill="x", pady=5)
        self.whitelist_proc.insert("1.0", "explorer.exe\nchrome.exe\nfirefox.exe\ncode.exe")

        # Resource limits
        limits_frame = ctk.CTkFrame(process_frame, fg_color="transparent")
        limits_frame.pack(fill="x", padx=40, pady=10)

        ctk.CTkLabel(
            limits_frame,
            text="Resource Limits:",
            font=ctk.CTkFont(size=14)
        ).pack(anchor="w")

        # CPU limit
        cpu_frame = ctk.CTkFrame(limits_frame, fg_color="transparent")
        cpu_frame.pack(fill="x", pady=5)

        ctk.CTkLabel(
            cpu_frame,
            text="Max CPU %:",
            width=120
        ).pack(side="left")

        self.cpu_limit = ctk.CTkSlider(
            cpu_frame,
            from_=10,
            to=100,
            number_of_steps=9
        )
        self.cpu_limit.pack(side="left", fill="x", expand=True, padx=10)
        self.cpu_limit.set(50)

        self.cpu_label = ctk.CTkLabel(cpu_frame, text="50%", width=50)
        self.cpu_label.pack(side="left")

        self.cpu_limit.configure(command=lambda v: self.cpu_label.configure(text=f"{int(v)}%"))

    def _create_network_permissions(self, parent):
        """Create network permissions section"""
        network_frame = ctk.CTkFrame(parent, corner_radius=15, fg_color="#2a2a2a")
        network_frame.pack(fill="x", pady=20)

        title = ctk.CTkLabel(
            network_frame,
            text="🌐 Network Permissions",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        title.pack(pady=(20, 10))

        # Network options
        self.block_network = ctk.CTkCheckBox(
            network_frame,
            text="Block unauthorized network access",
            font=ctk.CTkFont(size=14)
        )
        self.block_network.pack(anchor="w", padx=40, pady=5)
        self.block_network.select()

        self.monitor_upload = ctk.CTkCheckBox(
            network_frame,
            text="Monitor large uploads (potential data theft)",
            font=ctk.CTkFont(size=14)
        )
        self.monitor_upload.pack(anchor="w", padx=40, pady=5)
        self.monitor_upload.select()

        # Blocked domains
        domains_frame = ctk.CTkFrame(network_frame, fg_color="transparent")
        domains_frame.pack(fill="x", padx=40, pady=10)

        ctk.CTkLabel(
            domains_frame,
            text="Blocked Domains:",
            font=ctk.CTkFont(size=14)
        ).pack(anchor="w")

        self.blocked_domains = ctk.CTkTextbox(
            domains_frame,
            height=60,
            font=ctk.CTkFont(size=12)
        )
        self.blocked_domains.pack(fill="x", pady=(5, 20))
        self.blocked_domains.insert("1.0", "*.onion\n*.malware.com\nmega.nz")

    def _create_custom_rules(self, parent):
        """Create custom rules section"""
        custom_frame = ctk.CTkFrame(parent, corner_radius=15, fg_color="#2a2a2a")
        custom_frame.pack(fill="x", pady=20)

        title = ctk.CTkLabel(
            custom_frame,
            text="📝 Custom Rules",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        title.pack(pady=(20, 10))

        # Rule editor
        self.rule_editor = ctk.CTkTextbox(
            custom_frame,
            height=150,
            font=ctk.CTkFont(family="monospace", size=12)
        )
        self.rule_editor.pack(fill="x", padx=40, pady=10)

        # Sample rule
        sample_rule = """{
    "rule_name": "Block Crypto Miners",
    "conditions": {
        "process_name": ["*miner*", "*crypto*"],
        "cpu_usage": "> 80%"
    },
    "actions": ["terminate", "quarantine", "alert"]
}"""
        self.rule_editor.insert("1.0", sample_rule)

        # Save button
        save_btn = ctk.CTkButton(
            custom_frame,
            text="💾 Save Permissions",
            font=ctk.CTkFont(size=16),
            height=40,
            command=self._save_permissions
        )
        save_btn.pack(pady=(10, 30))

    def _update_security_level(self):
        """Update security level"""
        level = self.security_level.get()
        self.app.logger.info(f"Security level changed to: {level}")

        # Update enforcer settings
        if hasattr(self.app, 'monitor') and hasattr(self.app.monitor, 'enforcer'):
            self.app.monitor.enforcer.set_security_level(level.lower())

    def _save_permissions(self):
        """Save all permission settings"""
        try:
            # Gather all settings
            permissions = {
                'security_level': self.security_level.get(),
                'file_permissions': {
                    'allowed_extensions': self.allowed_ext.get("1.0", "end-1c").split(", "),
                    'blocked_extensions': self.blocked_ext.get("1.0", "end-1c").split(", "),
                    'protect_system': self.protect_system.get(),
                    'backup_delete': self.backup_delete.get()
                },
                'process_permissions': {
                    'whitelist': self.whitelist_proc.get("1.0", "end-1c").split("\n"),
                    'cpu_limit': int(self.cpu_limit.get())
                },
                'network_permissions': {
                    'block_unauthorized': self.block_network.get(),
                    'monitor_uploads': self.monitor_upload.get(),
                    'blocked_domains': self.blocked_domains.get("1.0", "end-1c").split("\n")
                },
                'custom_rules': self.rule_editor.get("1.0", "end-1c")
            }

            # Save to file
            with open("config/permissions.json", "w") as f:
                json.dump(permissions, f, indent=4)

            messagebox.showinfo("Success", "Permissions saved successfully!")
            self.app.logger.info("Permissions updated")

            # Apply permissions
            if hasattr(self.app, 'permissions'):
                self.app.permissions.load_permissions()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to save permissions: {str(e)}")
            self.app.logger.error(f"Failed to save permissions: {e}")
