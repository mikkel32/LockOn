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
    from tkinter import ttk

    def _map_color_kwargs(kwargs: dict[str, object]) -> None:
        """Translate ``customtkinter`` style keys to ``tkinter`` equivalents."""

        mapping = {
            "fg_color": "bg",
            "text_color": "fg",
            "border_width": "bd",
        }

        for ctk_key, tk_key in mapping.items():
            if ctk_key in kwargs:
                kwargs[tk_key] = kwargs.pop(ctk_key)

        # discard unsupported options
        for key in [
            "corner_radius",
            "border_color",
            "hover_color",
            "number_of_steps",
        ]:
            kwargs.pop(key, None)


    class _CTkWindow(tk.Tk):
        """Fallback root window supporting CTk options."""

        def __init__(self, *args, **kwargs) -> None:
            _map_color_kwargs(kwargs)
            super().__init__(*args, **kwargs)

        def configure(self, cnf=None, **kw):  # type: ignore[override]
            if cnf is None:
                cnf = {}
            _map_color_kwargs(cnf)
            _map_color_kwargs(kw)
            return super().configure(cnf, **kw)


    class _CTkFrame(tk.Frame):
        """Fallback frame supporting a subset of CTk options."""

        def __init__(self, master=None, *args, **kwargs):
            _map_color_kwargs(kwargs)
            super().__init__(master, *args, **kwargs)

        def configure(self, cnf=None, **kw):  # type: ignore[override]
            if cnf is None:
                cnf = {}
            _map_color_kwargs(cnf)
            _map_color_kwargs(kw)
            return super().configure(cnf, **kw)


    class _CTkLabel(tk.Label):
        """Fallback label with CTk option mapping."""

        def __init__(self, master=None, *args, **kwargs):
            _map_color_kwargs(kwargs)
            super().__init__(master, *args, **kwargs)

        def configure(self, cnf=None, **kw):  # type: ignore[override]
            if cnf is None:
                cnf = {}
            _map_color_kwargs(cnf)
            _map_color_kwargs(kw)
            return super().configure(cnf, **kw)


    class _CTkButton(tk.Button):
        """Fallback button mapping CTk options."""

        def __init__(self, master=None, *args, **kwargs):
            _map_color_kwargs(kwargs)
            super().__init__(master, *args, **kwargs)

        def configure(self, cnf=None, **kw):  # type: ignore[override]
            if cnf is None:
                cnf = {}
            _map_color_kwargs(cnf)
            _map_color_kwargs(kw)
            return super().configure(cnf, **kw)


    class _CTkProgressBar(tk.Scale):
        """Simple progress bar using :class:`tk.Scale`. Value range is 0..1."""

        def __init__(self, master=None, *args, **kwargs):
            _map_color_kwargs(kwargs)
            kwargs.setdefault("from_", 0.0)
            kwargs.setdefault("to", 1.0)
            kwargs.setdefault("orient", "horizontal")
            kwargs.setdefault("showvalue", False)
            super().__init__(master, *args, **kwargs)

        def set(self, value: float) -> None:
            tk.Scale.set(self, value)


    class _CTkSlider(tk.Scale):
        """Simplified slider implementation."""

        def __init__(self, master=None, *args, **kwargs):
            _map_color_kwargs(kwargs)
            kwargs.setdefault("orient", "horizontal")
            if "width" in kwargs:
                kwargs["length"] = kwargs.pop("width")
            super().__init__(master, *args, **kwargs)


    class _CTkTabview(tk.Frame):
        """Basic tab container used to group frames."""

        def __init__(self, master=None, *args, **kwargs):
            super().__init__(master, *args, **kwargs)
            self._tabs: dict[str, tk.Frame] = {}

        def add(self, name: str) -> None:
            frame = tk.Frame(self)
            frame.pack_forget()
            self._tabs[name] = frame

        def tab(self, name: str) -> tk.Frame:
            return self._tabs[name]


    class _SimpleCTk:
        """Very small subset of the ``customtkinter`` API."""

        CTk = _CTkWindow
        CTkFrame = _CTkFrame
        CTkButton = _CTkButton
        CTkLabel = _CTkLabel
        CTkCanvas = tk.Canvas
        CTkScrollbar = tk.Scrollbar
        CTkProgressBar = _CTkProgressBar
        CTkScrollableFrame = _CTkFrame
        CTkTextbox = tk.Text
        CTkOptionMenu = tk.OptionMenu
        CTkTabview = _CTkTabview
        CTkSlider = _CTkSlider
        CTkRadioButton = tk.Radiobutton
        CTkCheckBox = tk.Checkbutton

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

