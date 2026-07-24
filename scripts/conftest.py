"""pytest conftest: isolate host state and expose local source trees."""

import os
import sys
from pathlib import Path

import pytest

_scripts = str(Path(__file__).resolve().parent)
_src = str(Path(__file__).resolve().parent.parent / "cve-analyzer" / "src")
for p in (_scripts, _src):
    if p not in sys.path:
        sys.path.insert(0, p)


@pytest.fixture(scope="session", autouse=True)
def _ignore_host_git_configuration() -> None:
    """Keep fixture commits independent of user signing/hooks configuration."""

    previous = {
        name: os.environ.get(name)
        for name in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM")
    }
    os.environ["GIT_CONFIG_GLOBAL"] = os.devnull
    os.environ["GIT_CONFIG_NOSYSTEM"] = "1"
    yield
    for name, value in previous.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value
