# -*- coding: utf-8 -*-
"""Profile save/load for build configurations."""
import json
import os
from typing import Optional

from core.build_config import BuildConfig

HISTORY_PATH = os.path.expanduser("~/.ctfpacker_history.json")


class HistoryManager:
    """Manages saved build profiles in a JSON file."""

    def __init__(self, path: str = HISTORY_PATH):
        self._path = path
        self._data = self._load_file()

    def _load_file(self) -> dict:
        if os.path.exists(self._path):
            try:
                with open(self._path, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return {}
        return {}

    def _save_file(self):
        with open(self._path, "w") as f:
            json.dump(self._data, f, indent=2)
        os.chmod(self._path, 0o600)

    def list_profiles(self, mode: str) -> list:
        """Return profile names for the given mode."""
        return list(self._data.get(mode, {}).keys())

    def load_profile(self, mode: str, name: str) -> Optional[BuildConfig]:
        """Load a named profile, or None if not found."""
        profiles = self._data.get(mode, {})
        if name in profiles:
            return BuildConfig.from_dict(profiles[name])
        return None

    def save_profile(self, mode: str, name: str, config: BuildConfig):
        """Save a profile under the given mode and name. PFX password is never persisted."""
        if mode not in self._data:
            self._data[mode] = {}
        self._data[mode][name] = config.to_safe_dict()
        self._save_file()

    def delete_profile(self, mode: str, name: str):
        """Delete a profile."""
        if mode in self._data and name in self._data[mode]:
            del self._data[mode][name]
            self._save_file()

    # ── Import / Export ───────────────────────────────────────────────────

    SCHEMA_VERSION = 1

    def export_profile(self, mode: str, name: str) -> dict:
        """Return a portable dict for saving as a .ctfp file."""
        profiles = self._data.get(mode, {})
        if name not in profiles:
            raise KeyError(f"Profile '{name}' not found in mode '{mode}'")
        return {
            "ctfpacker_profile": self.SCHEMA_VERSION,
            "mode": mode,
            "name": name,
            "config": profiles[name],
        }

    def import_profile(self, data: dict) -> tuple:
        """Validate and merge a .ctfp dict. Returns (mode, name).
        Raises ValueError on bad schema. Caller must handle overwrite checks.
        """
        if data.get("ctfpacker_profile") != self.SCHEMA_VERSION:
            raise ValueError("Invalid or unsupported .ctfp file format.")
        mode = data.get("mode")
        name = data.get("name", "").strip()
        config = data.get("config")
        if not isinstance(mode, str) or mode not in ("staged", "stageless"):
            raise ValueError(f"Unknown mode '{mode}' in profile file.")
        if not name:
            raise ValueError("Profile file has no valid name.")
        if not isinstance(config, dict):
            raise ValueError("Profile file has no valid config block.")
        if mode not in self._data:
            self._data[mode] = {}
        self._data[mode][name] = config
        self._save_file()
        return mode, name
