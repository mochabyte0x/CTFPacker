# -*- coding: utf-8 -*-
"""Background build worker thread."""
from PyQt6.QtCore import QThread, pyqtSignal

from core.build_config import BuildConfig
from core.build_engine import BuildEngine


class BuildWorker(QThread):
    """Runs BuildEngine.build() in a background thread."""

    log_message = pyqtSignal(str, str)      # (message, level)
    build_finished = pyqtSignal(bool)       # success

    def __init__(self, config: BuildConfig, parent=None):
        super().__init__(parent)
        self._config = config

    def run(self):
        def log_cb(message, level):
            self.log_message.emit(message, level)

        engine = BuildEngine(log_cb)
        success = engine.build(self._config)
        self.build_finished.emit(success)
