"""Wheel build hook: bundle the dashboard UI when `frontend/dist` has been built.

`frontend/dist` is not in git, so `pip install git+...` has no UI to bundle: the wheel then serves the
API only and `asent doctor` / `asent dashboard` say so. CI runs `npm run build` first, so its wheel
artifact includes the UI. A force-included path must exist, hence a hook instead of pyproject.toml.
"""
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version, build_data):
        dist = Path(self.root) / "frontend" / "dist"
        if (dist / "index.html").is_file():
            build_data["force_include"][str(dist)] = "backend/_data/frontend/dist"
