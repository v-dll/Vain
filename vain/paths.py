import os
from pathlib import Path


def vain_home(override: str | None = None) -> Path:
    """Where Vain keeps its cache and scan state (``--home`` > $VAIN_HOME > ~/.vain)."""
    raw = override or os.environ.get("VAIN_HOME") or (Path.home() / ".vain")
    path = Path(raw).expanduser()
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path
