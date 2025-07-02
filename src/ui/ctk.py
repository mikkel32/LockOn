"""Compatibility layer for :mod:`customtkinter`.

This module tries to import ``customtkinter`` and exposes it as ``ctk``. When
the dependency is missing a minimal fallback using the standard ``tkinter``
module is provided so the rest of the application can still run.  The fallback
only implements a subset of the features used throughout the code base and does
not attempt to replicate the full appearance of ``customtkinter``.
"""

from __future__ import annotations

try:  # pragma: no cover - optional dependency
    import customtkinter as ctk  # type: ignore
except Exception:  # pragma: no cover - lightweight fallback
    import tkinter as tk

    class _SimpleCTk:
        """Very small subset of the ``customtkinter`` API."""

        # basic widget classes
        CTk = tk.Tk
        CTkFrame = tk.Frame
        CTkButton = tk.Button
        CTkLabel = tk.Label
        CTkCanvas = tk.Canvas
        CTkScrollbar = tk.Scrollbar
        CTkProgressBar = tk.Scale
        CTkScrollableFrame = tk.Frame
        CTkTextbox = tk.Text
        CTkOptionMenu = tk.OptionMenu
        CTkTabview = tk.Frame

        StringVar = tk.StringVar
        IntVar = tk.IntVar
        DoubleVar = tk.DoubleVar

        @staticmethod
        def CTkFont(*args, **kwargs):  # noqa: N802 - mimic class name
            return ("TkDefaultFont",)

        @staticmethod
        def set_appearance_mode(mode: str) -> None:  # noqa: D401 - simple stub
            """Stubbed configuration helper."""

        @staticmethod
        def set_default_color_theme(theme: str) -> None:  # noqa: D401
            """Stubbed configuration helper."""

    ctk = _SimpleCTk()

__all__ = ["ctk"]

