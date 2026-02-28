# -*- coding: utf-8 -*-
"""Main application window for CTFPacker GUI."""
import os
import sys
import time
import json
import subprocess as _sp
import shutil

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QSplitter, QWidget,
    QVBoxLayout, QHBoxLayout, QLabel, QStatusBar, QCheckBox
)
from PyQt6.QtCore import Qt, QTimer, QByteArray, QRectF
from PyQt6.QtGui import QKeySequence, QShortcut, QPixmap, QIcon, QPainter
from PyQt6.QtSvg import QSvgRenderer

from gui.theme import (
    STYLESHEET, ACCENT, ACCENT_DIM, ACCENT_BRIGHT,
    BG_BASE, BG_SURFACE, BG_ELEVATED, BG_HEADER,
    TEXT, TEXT_DIM, TEXT_MUTED, BORDER, GREEN, RED, ORANGE,
    # Nord compat aliases still used by status label colour strings
    FROST1, NORD3, NORD4, NORD0, NORD1,
)
from gui.widgets.staged_tab import StagedTab
from gui.widgets.stageless_tab import StagelessTab
from gui.widgets.log_panel import LogPanel
from gui.workers import BuildWorker
from gui.history import HistoryManager

GEOMETRY_PATH = os.path.expanduser("~/.ctfpacker_geometry.json")

# Locate assets/: 1) gui/assets/ (installed via pipx), 2) Linux/assets/, 3) repo root (dev)
_HERE = os.path.dirname(os.path.abspath(__file__))
_ASSET_CANDIDATES = [
    os.path.join(_HERE, "assets"),                       # installed: inside gui package
    os.path.normpath(os.path.join(_HERE, "..", "assets")),  # Linux/assets/
    os.path.normpath(os.path.join(_HERE, "..", "..", "assets")),  # repo root (dev)
]
ASSETS_DIR      = next((d for d in _ASSET_CANDIDATES if os.path.isdir(d)),
                        _ASSET_CANDIDATES[0])
LOGO_ICON_PATH   = os.path.join(ASSETS_DIR, "Logo.png")
FULL_LOGO_PATH   = os.path.join(ASSETS_DIR, "Full-Logo.svg")
FULL_LOGO_RED    = os.path.join(ASSETS_DIR, "Full-Logo-red-black.svg")


def _render_full_logo(height: int = 52) -> QPixmap:
    """Render Full-Logo-red-black.svg cropped to content.

    Red gradient wordmark + black icon.  Black icon fill is recoloured
    to white so it shows on the dark header; the red gradient text is
    kept as-is.
    """
    src = FULL_LOGO_RED if os.path.isfile(FULL_LOGO_RED) else FULL_LOGO_PATH
    if not os.path.isfile(src):
        return QPixmap()
    with open(src, "r") as fh:
        svg = fh.read()
    svg = svg.replace('viewBox="0 0 1024 768"', 'viewBox="40 228 858 310"')
    svg = svg.replace("fill: rgb(0,0,0)", "fill: rgb(255,255,255)")
    ratio = 858 / 310
    w = int(height * ratio)
    renderer = QSvgRenderer(QByteArray(svg.encode("utf-8")))
    pix = QPixmap(w, height)
    pix.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pix)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    renderer.render(painter, QRectF(0, 0, w, height))
    painter.end()
    return pix




class MainWindow(QMainWindow):
    """CTFPacker v2.0 main window."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("CTFPacker")
        self.setMinimumSize(960, 720)

        # Window icon
        if os.path.isfile(LOGO_ICON_PATH):
            self.setWindowIcon(QIcon(LOGO_ICON_PATH))

        self._worker = None
        self._history = HistoryManager()
        self._build_start_time = 0
        self._elapsed_timer = QTimer(self)
        self._elapsed_timer.setInterval(1000)
        self._elapsed_timer.timeout.connect(self._update_elapsed)
        self._splitter = None

        self._setup_ui()
        self._setup_statusbar()
        self._setup_shortcuts()
        self._restore_geometry()

    def _setup_ui(self):
        central = QWidget()
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # -- Header banner --
        header = QWidget()
        header.setFixedHeight(64)
        header.setStyleSheet(
            f"background-color: {BG_HEADER};"
            f"border-bottom: 1px solid {BORDER};"
        )
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(16, 0, 20, 0)
        header_layout.setSpacing(0)

        # Full-Logo SVG: icon + wordmark rendered as a single pixmap
        logo_label = QLabel()
        logo_pix = _render_full_logo(height=48)
        if not logo_pix.isNull():
            logo_label.setPixmap(logo_pix)
            logo_label.setFixedSize(logo_pix.size())
        else:
            # Fallback: plain text if assets not found
            logo_label.setText("CTFPACKER")
            logo_label.setObjectName("headerTitle")
        logo_label.setStyleSheet("background: transparent;")
        header_layout.addWidget(logo_label)

        header_layout.addStretch()

        badge = QLabel("v2.0")
        badge.setObjectName("headerBadge")
        header_layout.addWidget(badge)

        main_layout.addWidget(header)

        # -- Splitter: tabs + log --
        self._splitter = QSplitter(Qt.Orientation.Vertical)

        self._tabs = QTabWidget()
        self._staged_tab = StagedTab(self._history)
        self._stageless_tab = StagelessTab(self._history)
        self._tabs.addTab(self._staged_tab, "Staged")
        self._tabs.addTab(self._stageless_tab, "Stageless")

        self._log_panel = LogPanel()

        self._splitter.addWidget(self._tabs)
        self._splitter.addWidget(self._log_panel)
        self._splitter.setStretchFactor(0, 3)
        self._splitter.setStretchFactor(1, 1)

        main_layout.addWidget(self._splitter, stretch=1)
        self.setCentralWidget(central)

        # Connect signals
        self._staged_tab.build_requested.connect(self._start_build)
        self._stageless_tab.build_requested.connect(self._start_build)
        self._staged_tab.profile_imported.connect(self._on_profile_imported)
        self._stageless_tab.profile_imported.connect(self._on_profile_imported)

    def _setup_statusbar(self):
        self._statusbar = QStatusBar()
        self.setStatusBar(self._statusbar)

        # State dot — 8 px circle, colour reflects build state
        self._dot_label = QLabel("●")
        self._dot_label.setToolTip("Build state")
        self._dot_label.setStyleSheet(
            f"color: {TEXT_MUTED}; font-size: 8px; padding: 0 4px 0 6px;"
        )
        self._statusbar.addWidget(self._dot_label)

        self._status_label = QLabel("Ready")
        self._elapsed_label = QLabel("")

        self._notify_check = QCheckBox("Notifications")
        self._notify_check.setChecked(True)
        self._notify_check.setToolTip("Show desktop notifications when builds finish")

        self._statusbar.addWidget(self._status_label, stretch=1)
        self._statusbar.addPermanentWidget(self._elapsed_label)
        self._statusbar.addPermanentWidget(self._notify_check)

    def _setup_shortcuts(self):
        QShortcut(QKeySequence("Ctrl+L"), self, self._log_panel.clear)

    def _on_profile_imported(self):
        """Refresh both tabs' profile combos after any import."""
        self._staged_tab._refresh_profiles()
        self._stageless_tab._refresh_profiles()

    def _start_build(self, config):
        if self._worker and self._worker.isRunning():
            return

        self._log_panel.clear()

        # Log build summary
        self._log_panel.append_log("--- Build Configuration ---", "info")
        self._log_panel.append_log(f"  Mode:       {config.mode}", "info")
        self._log_panel.append_log(f"  Format:     {config.format}", "info")
        self._log_panel.append_log(f"  Injection:  {config.inject_method}", "info")
        if config.inject_method == "apc":
            self._log_panel.append_log(f"  Target:     {config.target_process}", "info")
        self._log_panel.append_log(f"  Encrypt:    {'Yes' if config.encrypt else 'No'}", "info")
        self._log_panel.append_log(f"  Scramble:   {'Yes' if config.scramble else 'No'}", "info")
        self._log_panel.append_log(f"  Output:     {config.output or 'ctfloader'}", "info")
        if config.mode == "staged":
            proto = "https" if config.https else "http"
            self._log_panel.append_log(
                f"  Download:   {proto}://{config.ip_address}:{config.port}{config.path}", "info")
        self._log_panel.append_log("----------------------------", "info")

        self._log_panel.set_building(True)
        self._set_build_enabled(False)

        self._dot_label.setStyleSheet(f"color: {ORANGE}; font-size: 8px; padding: 0 4px 0 6px;")
        self._status_label.setText("Building...")
        self._status_label.setStyleSheet(f"color: {ACCENT};")
        self._build_start_time = time.time()
        self._update_elapsed()
        self._elapsed_timer.start()

        self._last_config = config
        self._worker = BuildWorker(config)
        self._worker.log_message.connect(self._log_panel.append_log)
        self._worker.build_finished.connect(self._on_build_finished)
        self._worker.start()

    def _on_build_finished(self, success: bool):
        self._elapsed_timer.stop()
        self._log_panel.set_building(False)
        self._set_build_enabled(True)

        elapsed = time.time() - self._build_start_time
        elapsed_str = f"{elapsed:.1f}s"

        if success:
            # Resolve output path for display
            cfg = self._last_config
            base = cfg.output or "ctfloader"
            root, _ = os.path.splitext(base)
            ext = ".dll" if cfg.format == "DLL" else ".exe"
            out_file = os.path.abspath(root + ext)
            output_dir = os.path.dirname(out_file)

            self._log_panel.append_log("Build completed successfully!", "success")
            self._log_panel.append_log(f"Output: {out_file}", "success")
            self._dot_label.setStyleSheet(f"color: {GREEN}; font-size: 8px; padding: 0 4px 0 6px;")
            self._status_label.setText(f"\u2714  Build succeeded ({elapsed_str})")
            self._status_label.setStyleSheet(f"color: {GREEN};")
            self._log_panel.show_open_folder(output_dir)
        else:
            self._log_panel.append_log("Build failed.", "error")
            self._dot_label.setStyleSheet(f"color: {RED}; font-size: 8px; padding: 0 4px 0 6px;")
            self._status_label.setText(f"\u2717  Build failed ({elapsed_str})")
            self._status_label.setStyleSheet(f"color: {RED};")

        self._elapsed_label.setText("")
        self._send_notification(success, elapsed_str)

    def _send_notification(self, success: bool, elapsed_str: str):
        """Send a desktop notification when build finishes."""
        if not self._notify_check.isChecked():
            return

        if success:
            title = "CTFPacker - Build Succeeded"
            body = f"Build completed in {elapsed_str}"
        else:
            title = "CTFPacker - Build Failed"
            body = f"Build failed after {elapsed_str}"

        try:
            if sys.platform == "linux" and shutil.which("notify-send"):
                icon = "dialog-information" if success else "dialog-error"
                _sp.Popen(["notify-send", "-i", icon, title, body],
                          stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
            elif sys.platform == "darwin":
                _sp.Popen([
                    "osascript", "-e",
                    f'display notification "{body}" with title "{title}"'
                ], stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
        except OSError:
            pass  # Notification is best-effort

    def _update_elapsed(self):
        elapsed = time.time() - self._build_start_time
        self._elapsed_label.setText(f"Elapsed: {elapsed:.0f}s")

    def _set_build_enabled(self, enabled: bool):
        self._staged_tab.set_build_enabled(enabled)
        self._stageless_tab.set_build_enabled(enabled)

    # -- Window geometry persistence --

    def _save_geometry(self):
        data = {
            "window_geometry": self.saveGeometry().toBase64().data().decode(),
            "splitter_state": self._splitter.saveState().toBase64().data().decode()
                              if self._splitter else None,
            "notifications": self._notify_check.isChecked(),
        }
        try:
            with open(GEOMETRY_PATH, "w") as f:
                json.dump(data, f)
        except OSError:
            pass

    def _restore_geometry(self):
        try:
            with open(GEOMETRY_PATH, "r") as f:
                data = json.load(f)
            if "window_geometry" in data:
                self.restoreGeometry(QByteArray.fromBase64(data["window_geometry"].encode()))
            if "splitter_state" in data and data["splitter_state"] and self._splitter:
                self._splitter.restoreState(QByteArray.fromBase64(data["splitter_state"].encode()))
            if "notifications" in data:
                self._notify_check.setChecked(data["notifications"])
        except (OSError, json.JSONDecodeError, KeyError):
            pass

    def closeEvent(self, event):
        self._save_geometry()
        super().closeEvent(event)


def run_gui():
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLESHEET)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
