# -*- coding: utf-8 -*-
"""Shared GUI widget helpers."""
import os

from PyQt6.QtWidgets import (
    QHBoxLayout, QVBoxLayout, QLineEdit, QPushButton, QFileDialog,
    QWidget, QLabel, QSizePolicy,
    QMessageBox, QInputDialog, QSpacerItem,
)
from PyQt6.QtCore import Qt, QMimeData, pyqtSignal
from PyQt6.QtGui import QPainter, QPen, QColor, QFont

from gui.theme import (
    BG_BASE, BG_SURFACE, BG_ELEVATED, BORDER, BORDER_SUB,
    ACCENT, ACCENT_DIM, ACCENT_BRIGHT,
    TEXT, TEXT_DIM, TEXT_MUTED,
    GREEN, RED,
    # Nord compat aliases
    NORD0, NORD1, NORD2, NORD3, NORD4,
    FROST1, FROST2, FROST3,
)


class DropLineEdit(QLineEdit):
    """QLineEdit that accepts drag-and-drop files."""

    def __init__(self, file_filter_exts=None, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        # e.g. ['.bin', '.pfx'] — if None, accept any file
        self._filter_exts = file_filter_exts

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if urls and urls[0].isLocalFile():
                path = urls[0].toLocalFile()
                if self._filter_exts is None or any(path.lower().endswith(e) for e in self._filter_exts):
                    event.acceptProposedAction()
                    return
        event.ignore()

    def dragMoveEvent(self, event):
        event.acceptProposedAction()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls and urls[0].isLocalFile():
            self.setText(urls[0].toLocalFile())
            event.acceptProposedAction()


class DropZone(QWidget):
    """A visual drag-and-drop zone for payload files.

    Shows a dashed-border area with a hint label. Highlights on drag-over.
    Displays the filename once a file is selected. Includes a Browse button.
    """

    path_changed = pyqtSignal(str)

    def __init__(self, file_filter: str = "All Files (*)",
                 filter_exts=None,
                 hint_text: str = "Drag & drop shellcode (.bin) here",
                 browse_title: str = "Select file",
                 parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self._file_filter = file_filter
        self._filter_exts = filter_exts  # e.g. ['.bin']
        self._hint_text = hint_text
        self._browse_title = browse_title
        self._path = ""
        self._dragging = False

        self.setMinimumHeight(110)
        self.setSizePolicy(QSizePolicy.Policy.Expanding,
                           QSizePolicy.Policy.Fixed)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        # Internal layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(4)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Upload arrow icon (hidden once a file is selected)
        self._icon_label = QLabel("⬆")
        self._icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._icon_label.setStyleSheet(
            f"color: {ACCENT}; font-size: 18px; background: transparent; border: none;")
        layout.addWidget(self._icon_label)

        # Primary hint text
        self._hint_label = QLabel(hint_text)
        self._hint_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._hint_label.setStyleSheet(
            f"color: {TEXT_DIM}; font-size: 13px; background: transparent; border: none;")
        layout.addWidget(self._hint_label)

        # "or browse" sub-hint
        self._sub_label = QLabel("or click to browse")
        self._sub_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._sub_label.setStyleSheet(
            f"color: {ACCENT}; font-size: 11px; background: transparent; border: none;")
        layout.addWidget(self._sub_label)

        # Clear button — only visible when a file is loaded
        self._clear_btn = QPushButton("× clear")
        self._clear_btn.setObjectName("deleteButton")
        self._clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._clear_btn.setFixedWidth(70)
        self._clear_btn.setStyleSheet(
            self._clear_btn.styleSheet() +
            "QPushButton#deleteButton { font-size: 10px; padding: 2px 8px; }")
        self._clear_btn.setVisible(False)
        self._clear_btn.clicked.connect(self._clear_file)
        layout.addWidget(self._clear_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        # File path display (hidden until file selected)
        self._file_label = QLabel("")
        self._file_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._file_label.setWordWrap(True)
        self._file_label.setStyleSheet(
            f"color: {GREEN}; font-size: 12px; font-weight: bold; "
            f"background: transparent; border: none;")
        self._file_label.setVisible(False)
        layout.addWidget(self._file_label)

    def text(self) -> str:
        """Return the current file path (API compat with QLineEdit)."""
        return self._path

    def setText(self, path: str):
        """Set the file path programmatically."""
        self._path = path
        self._update_display()
        self.path_changed.emit(path)

    @property
    def textChanged(self):
        """Signal compat — returns path_changed so callers can connect."""
        return self.path_changed

    def setProperty(self, name, value):
        super().setProperty(name, value)
        if name == "validationError":
            self.update()

    def _clear_file(self):
        """Remove the currently selected file."""
        self._path = ""
        self._update_display()
        self.path_changed.emit("")

    def _update_display(self):
        if self._path:
            filename = os.path.basename(self._path)
            # Elide long paths so they don't break the layout
            max_path_chars = 60
            display_path = (self._path if len(self._path) <= max_path_chars
                            else f"…{self._path[-(max_path_chars - 1):]}") 
            self._icon_label.setVisible(False)
            self._hint_label.setText(filename)
            self._hint_label.setStyleSheet(
                f"color: {ACCENT}; font-size: 13px; font-weight: bold; "
                f"background: transparent; border: none;")
            self._sub_label.setText(display_path)
            self._sub_label.setStyleSheet(
                f"color: {TEXT_DIM}; font-size: 10px; "
                f"background: transparent; border: none;")
            self._clear_btn.setVisible(True)
            self._file_label.setVisible(False)
        else:
            self._icon_label.setVisible(True)
            self._hint_label.setText(self._hint_text)
            self._hint_label.setStyleSheet(
                f"color: {TEXT_DIM}; font-size: 13px; "
                f"background: transparent; border: none;")
            self._sub_label.setText("or click to browse")
            self._sub_label.setStyleSheet(
                f"color: {ACCENT}; font-size: 11px; "
                f"background: transparent; border: none;")
            self._clear_btn.setVisible(False)
            self._file_label.setVisible(False)
        self.update()

    # -- Paint the dashed border --

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        validation_error = self.property("validationError")

        if self._dragging:
            border_color = QColor(ACCENT)
            bg_color = QColor(ACCENT)
            bg_color.setAlpha(18)
        elif validation_error:
            border_color = QColor(RED)
            bg_color = QColor(RED)
            bg_color.setAlpha(18)
        elif self._path:
            border_color = QColor(GREEN)
            bg_color = QColor(GREEN)
            bg_color.setAlpha(12)
        else:
            border_color = QColor(BORDER)
            bg_color = QColor(BG_SURFACE)

        # Background fill
        painter.setBrush(bg_color)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRoundedRect(self.rect().adjusted(1, 1, -1, -1), 2, 2)

        # Dashed border — tighter dash pattern for a crisper look
        pen = QPen(border_color, 1, Qt.PenStyle.CustomDashLine)
        pen.setDashPattern([5, 3])
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawRoundedRect(self.rect().adjusted(1, 1, -1, -1), 2, 2)

        # If dragging: draw a solid 2px outer accent ring on top
        if self._dragging:
            solid_pen = QPen(QColor(ACCENT), 2, Qt.PenStyle.SolidLine)
            painter.setPen(solid_pen)
            painter.drawRoundedRect(self.rect().adjusted(1, 1, -1, -1), 2, 2)

        painter.end()

    # -- Mouse click = browse --

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            path, _ = QFileDialog.getOpenFileName(
                self, self._browse_title, "",
                self._file_filter)
            if path:
                self.setText(path)

    # -- Drag & drop --

    def _is_valid_file(self, path: str) -> bool:
        if self._filter_exts is None:
            return True
        return any(path.lower().endswith(e) for e in self._filter_exts)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if urls and urls[0].isLocalFile():
                if self._is_valid_file(urls[0].toLocalFile()):
                    self._dragging = True
                    self.update()
                    event.acceptProposedAction()
                    return
        event.ignore()

    def dragMoveEvent(self, event):
        event.acceptProposedAction()

    def dragLeaveEvent(self, event):
        self._dragging = False
        self.update()

    def dropEvent(self, event):
        self._dragging = False
        urls = event.mimeData().urls()
        if urls and urls[0].isLocalFile():
            path = urls[0].toLocalFile()
            if self._is_valid_file(path):
                self.setText(path)
                event.acceptProposedAction()
                return
        self.update()
        event.ignore()


def file_picker_row(parent: QWidget, label: str = "Browse...",
                    file_filter: str = "All Files (*)",
                    save_mode: bool = False) -> tuple:
    """
    Create a file picker row: DropLineEdit + Browse button.
    Returns (layout, line_edit) so the caller can read the path.
    """
    layout = QHBoxLayout()
    layout.setContentsMargins(0, 0, 0, 0)

    # Extract extensions from file_filter for drag-drop validation
    # e.g. "Binary Files (*.bin);;All Files (*)" -> ['.bin']
    filter_exts = None
    if file_filter and "*." in file_filter:
        import re
        exts = re.findall(r'\*\.(\w+)', file_filter)
        if exts:
            filter_exts = [f'.{e.lower()}' for e in exts]

    line_edit = DropLineEdit(file_filter_exts=filter_exts, parent=parent)
    line_edit.setPlaceholderText(label)

    browse_btn = QPushButton("Browse")
    browse_btn.setObjectName("browseButton")
    browse_btn.setFixedWidth(80)

    def on_browse():
        if save_mode:
            path, _ = QFileDialog.getSaveFileName(parent, label, "", file_filter)
        else:
            path, _ = QFileDialog.getOpenFileName(parent, label, "", file_filter)
        if path:
            line_edit.setText(path)

    browse_btn.clicked.connect(on_browse)

    layout.addWidget(line_edit, stretch=1)
    layout.addWidget(browse_btn)

    return layout, line_edit


# ── Dialog helpers ──────────────────────────────────────────────────────────────
# Qt does not reliably honour stylesheet min-width on QMessageBox.
# The only reliable fix is to inject a spacer into the grid layout.
_DLG_MIN_W = 500


def _widen(msg):
    """Inject a horizontal spacer to enforce a minimum dialog width."""
    spacer = QSpacerItem(_DLG_MIN_W, 0,
                         QSizePolicy.Policy.Minimum,
                         QSizePolicy.Policy.Expanding)
    layout = msg.layout()
    layout.addItem(spacer, layout.rowCount(), 0, 1, layout.columnCount())


def dlg_warn(parent, title: str, text: str):
    """Warning dialog with guaranteed minimum width."""
    msg = QMessageBox(parent)
    msg.setWindowTitle(title)
    msg.setText(text)
    msg.setIcon(QMessageBox.Icon.Warning)
    _widen(msg)
    msg.exec()


def dlg_error(parent, title: str, text: str):
    """Error dialog with guaranteed minimum width."""
    msg = QMessageBox(parent)
    msg.setWindowTitle(title)
    msg.setText(text)
    msg.setIcon(QMessageBox.Icon.Critical)
    _widen(msg)
    msg.exec()


def dlg_info(parent, title: str, text: str):
    """Information dialog with guaranteed minimum width."""
    msg = QMessageBox(parent)
    msg.setWindowTitle(title)
    msg.setText(text)
    msg.setIcon(QMessageBox.Icon.Information)
    _widen(msg)
    msg.exec()


def dlg_ask(parent, title: str, text: str, default_yes: bool = False) -> bool:
    """Yes/No question dialog. Returns True if user clicked Yes."""
    msg = QMessageBox(parent)
    msg.setWindowTitle(title)
    msg.setText(text)
    msg.setIcon(QMessageBox.Icon.Question)
    msg.setStandardButtons(
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
    msg.setDefaultButton(
        QMessageBox.StandardButton.Yes if default_yes
        else QMessageBox.StandardButton.No)
    _widen(msg)
    return msg.exec() == QMessageBox.StandardButton.Yes


def dlg_text(parent, title: str, label: str, default: str = "") -> tuple:
    """Text-input dialog. Returns (text, ok) like QInputDialog.getText."""
    dlg = QInputDialog(parent)
    dlg.setWindowTitle(title)
    dlg.setLabelText(label)
    dlg.setTextValue(default)
    dlg.setMinimumWidth(420)
    ok = dlg.exec() == QInputDialog.DialogCode.Accepted
    return dlg.textValue(), ok
