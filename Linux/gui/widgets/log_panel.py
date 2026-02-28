# -*- coding: utf-8 -*-
"""Color-coded build log panel with timestamps and export."""
import os
from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QTextEdit, QPushButton, QHBoxLayout,
    QProgressBar, QFileDialog, QLabel, QFrame
)
from PyQt6.QtGui import QTextCursor, QPixmap, QPainter
from PyQt6.QtCore import Qt, pyqtSignal

from gui.theme import GREEN, RED, YELLOW, BLUE, TEXT, CRUST, NORD3, FROST1, TEXT_MUTED, BORDER_SUB, ACCENT_DIM

# Locate Logo.png: gui/assets/ (installed), then fallback to dev repo layout
_HERE = os.path.dirname(os.path.abspath(__file__))
_LOGO_CANDIDATES = [
    os.path.normpath(os.path.join(_HERE, "..", "assets", "Logo.png")),         # installed: gui/assets/
    os.path.normpath(os.path.join(_HERE, "..", "..", "assets", "Logo.png")),   # Linux/assets/
    os.path.normpath(os.path.join(_HERE, "..", "..", "..", "assets", "Logo.png")),  # repo root (dev)
]
_LOGO_PATH = next((p for p in _LOGO_CANDIDATES if os.path.isfile(p)), _LOGO_CANDIDATES[0])


class _WatermarkTextEdit(QTextEdit):
    """QTextEdit that paints Logo.png as a centred, low-opacity watermark."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._watermark: QPixmap | None = None
        if os.path.isfile(_LOGO_PATH):
            pix = QPixmap(_LOGO_PATH)
            if not pix.isNull():
                # Pre-scale once to a fixed display size
                self._watermark = pix.scaled(
                    180, 180,
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation,
                )

    def paintEvent(self, event):
        """Draw watermark behind the text."""
        if self._watermark:
            painter = QPainter(self.viewport())
            painter.setOpacity(0.07)
            vp = self.viewport().rect()
            x = (vp.width()  - self._watermark.width())  // 2
            y = (vp.height() - self._watermark.height()) // 2
            painter.drawPixmap(x, y, self._watermark)
            painter.end()
        super().paintEvent(event)




# Level -> color mapping
LEVEL_COLORS = {
    "info": BLUE,
    "success": GREEN,
    "warning": YELLOW,
    "error": RED,
}


class LogPanel(QWidget):
    """Read-only, monospace log panel with color-coded, timestamped output."""

    open_folder_requested = pyqtSignal(str)  # emits folder path

    def __init__(self, parent=None):
        super().__init__(parent)
        self._raw_lines = []  # plain text for export

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Section header
        panel_header = QWidget()
        panel_header.setStyleSheet(
            f"background-color: transparent;"
            f"border-bottom: 1px solid {BORDER_SUB};"
        )
        ph_layout = QHBoxLayout(panel_header)
        ph_layout.setContentsMargins(10, 4, 10, 4)
        ph_label = QLabel("BUILD OUTPUT")
        ph_label.setObjectName("sectionLabel")
        ph_layout.addWidget(ph_label)
        ph_layout.addStretch()
        layout.addWidget(panel_header)

        # Progress bar (indeterminate, hidden by default)
        self._progress = QProgressBar()
        self._progress.setRange(0, 0)  # indeterminate
        self._progress.setFixedHeight(6)
        self._progress.setTextVisible(False)
        self._progress.hide()
        layout.addWidget(self._progress)

        # Toolbar
        toolbar = QHBoxLayout()
        toolbar.setContentsMargins(4, 4, 4, 2)

        self._open_folder_btn = QPushButton("Open Output Folder")
        self._open_folder_btn.setFixedWidth(160)
        self._open_folder_btn.hide()
        self._open_folder_btn.clicked.connect(self._on_open_folder)
        toolbar.addWidget(self._open_folder_btn)

        toolbar.addStretch()

        save_btn = QPushButton("Save Log")
        save_btn.setFixedWidth(90)
        save_btn.clicked.connect(self._save_log)
        toolbar.addWidget(save_btn)

        clear_btn = QPushButton("Clear Log")
        clear_btn.setFixedWidth(90)
        clear_btn.clicked.connect(self.clear)
        toolbar.addWidget(clear_btn)

        layout.addLayout(toolbar)

        # Text area
        self._text = _WatermarkTextEdit()
        self._text.setReadOnly(True)
        self._text.setStyleSheet(f"""
            QTextEdit {{
                background-color: {CRUST};
                color: {TEXT};
                font-family: "Cascadia Code", "Fira Code", "Consolas", monospace;
                font-size: 12px;
                border: none;
                padding: 8px;
            }}
        """)
        layout.addWidget(self._text)

        self._output_folder = ""

    def append_log(self, message: str, level: str = "info"):
        """Append a color-coded, timestamped log line and auto-scroll."""
        color = LEVEL_COLORS.get(level, TEXT)
        ts = datetime.now().strftime("%H:%M:%S")
        ts_html = f'<span style="color:{NORD3};">[{ts}]</span>'
        msg_html = f'<span style="color:{color};">&nbsp;{self._escape(message)}</span>'
        self._text.append(f'{ts_html}{msg_html}')
        self._text.moveCursor(QTextCursor.MoveOperation.End)
        self._raw_lines.append(f"[{ts}] {message}")

    def clear(self):
        self._text.clear()
        self._raw_lines.clear()
        self._open_folder_btn.hide()
        self._output_folder = ""

    def set_building(self, building: bool):
        """Show/hide the indeterminate progress bar."""
        self._progress.setVisible(building)

    def show_open_folder(self, folder: str):
        """Show the 'Open Output Folder' button after a successful build."""
        self._output_folder = folder
        self._open_folder_btn.show()

    def _on_open_folder(self):
        if self._output_folder and os.path.isdir(self._output_folder):
            import subprocess
            import sys
            if sys.platform == "linux":
                subprocess.Popen(["xdg-open", self._output_folder])
            elif sys.platform == "darwin":
                subprocess.Popen(["open", self._output_folder])
            else:
                os.startfile(self._output_folder)

    def _save_log(self):
        if not self._raw_lines:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Build Log", "build_log.txt", "Text Files (*.txt);;All Files (*)")
        if path:
            with open(path, "w") as f:
                f.write("\n".join(self._raw_lines))

    @staticmethod
    def _escape(text: str) -> str:
        return (text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace(" ", "&nbsp;")
                .replace("\t", "&nbsp;&nbsp;&nbsp;&nbsp;"))
