import builtins
import importlib
import sys
import types


def test_ctk_window_maps_options(monkeypatch):
    """CTk fallback should map style options to Tk names."""

    # Force ImportError for customtkinter
    real_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "customtkinter":
            raise ImportError
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    class DummyTk:
        def __init__(self, *args, **kwargs):
            self.kwargs = kwargs
            self.configure_calls = []

        def configure(self, cnf=None, **kw):
            if cnf is None:
                cnf = {}
            self.configure_calls.append({**cnf, **kw})

    tkmod = types.SimpleNamespace(
        Tk=DummyTk,
        Frame=object,
        Label=object,
        Button=object,
        Canvas=object,
        Scrollbar=object,
        Scale=object,
        Text=object,
        OptionMenu=object,
        Radiobutton=object,
        Checkbutton=object,
        StringVar=object,
        IntVar=object,
        DoubleVar=object,
    )
    tkmod.ttk = types.SimpleNamespace()

    monkeypatch.setitem(sys.modules, "tkinter", tkmod)
    monkeypatch.setitem(sys.modules, "tkinter.ttk", tkmod.ttk)

    sys.modules.pop("src.ui.ctk", None)
    ctk = importlib.import_module("src.ui.ctk")

    win = ctk.ctk.CTk()
    win.configure(fg_color="red", text_color="blue", border_width=3)

    assert win.configure_calls == [{"bg": "red", "fg": "blue", "bd": 3}]
