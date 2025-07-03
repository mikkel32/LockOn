from pathlib import Path

# Project root directory assuming this file lives in src/utils
ROOT_DIR = Path(__file__).resolve().parents[2]


def resource_path(*parts: str | Path) -> Path:
    """Return an absolute path inside the project for given *parts*."""
    flat_parts = []
    for p in parts:
        if isinstance(p, Path):
            flat_parts.extend(p.parts)
        else:
            flat_parts.append(p)
    return ROOT_DIR.joinpath(*flat_parts)
