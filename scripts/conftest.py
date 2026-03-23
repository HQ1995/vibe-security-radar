"""pytest conftest: ensure scripts/ and cve-analyzer/src/ are importable."""
import sys
from pathlib import Path

_scripts = str(Path(__file__).resolve().parent)
_src = str(Path(__file__).resolve().parent.parent / "cve-analyzer" / "src")
for p in (_scripts, _src):
    if p not in sys.path:
        sys.path.insert(0, p)
