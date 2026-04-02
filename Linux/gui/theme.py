# -*- coding: utf-8 -*-
"""CTFPacker GUI theme — Havoc-inspired."""

# ── Colour Palette ────────────────────────────────────────────────────────────
# Background hierarchy  (very dark blue-black, like Havoc C2)
BG_BASE     = "#12141a"   # root background
BG_SURFACE  = "#1a1d24"   # panels / group boxes
BG_ELEVATED = "#22252e"   # inputs, combos, toolbar areas
BG_HEADER   = "#0d0f13"   # top header strip
BG_CRUST    = "#0a0c10"   # log panel background

# Borders
BORDER      = "#2e3240"   # default border
BORDER_SUB  = "#1e2029"   # subtle separator

# Text
TEXT        = "#c9d1d9"   # primary
TEXT_DIM    = "#7d8590"   # secondary / placeholder
TEXT_MUTED  = "#3d444d"   # disabled / timestamps

# Accent — crimson red (matches logo)
ACCENT        = "#e83535"   # primary accent
ACCENT_BRIGHT = "#f55050"   # hover highlight
ACCENT_DIM    = "#9e1f1f"   # pressed / dim

# Status colours
GREEN   = "#3fb950"   # success
RED     = "#f0622f"   # error  (orange-red — distinct from accent)
YELLOW  = "#d29922"   # warning
ORANGE  = "#db6d28"   # info-alt

# ── Aliases (backwards-compat with widgets that import Nord names) ─────────────
NORD0  = BG_BASE
NORD1  = BG_SURFACE
NORD2  = BG_ELEVATED
NORD3  = TEXT_MUTED
NORD4  = TEXT
NORD5  = TEXT
NORD6  = TEXT
FROST0 = ACCENT_DIM
FROST1 = ACCENT
FROST2 = ACCENT
FROST3 = ACCENT_DIM
PURPLE = "#bc8cff"
BASE   = BG_BASE
MANTLE = BG_HEADER
CRUST  = BG_CRUST
BLUE   = ACCENT

STYLESHEET = f"""
/* ── Root ──────────────────────────────────────────────────────────────── */
QMainWindow, QWidget {{
    background-color: {BG_BASE};
    color: {TEXT};
    font-family: "Inter", "Segoe UI", "Ubuntu", sans-serif;
    font-size: 13px;
}}

/* ── Tabs ───────────────────────────────────────────────────────────────── */
QTabWidget::pane {{
    border: none;
    border-top: 2px solid {BORDER};
    background-color: {BG_BASE};
}}

QTabBar {{
    background-color: {BG_HEADER};
}}

QTabBar::tab {{
    background-color: transparent;
    color: {TEXT_DIM};
    padding: 9px 24px;
    border: none;
    border-bottom: 2px solid transparent;
    margin-right: 0px;
    font-weight: 600;
    letter-spacing: 0.5px;
    text-transform: uppercase;
    font-size: 11px;
}}

QTabBar::tab:selected {{
    color: {ACCENT};
    border-bottom: 2px solid {ACCENT};
    background-color: transparent;
}}

QTabBar::tab:hover:!selected {{
    color: {TEXT};
    background-color: {BG_ELEVATED};
}}

/* ── Group Boxes ─────────────────────────────────────────────────────────── */
QGroupBox {{
    border: 1px solid {BORDER};
    border-left: 3px solid {ACCENT_DIM};
    border-radius: 2px;
    margin-top: 14px;
    padding-top: 14px;
    background-color: {BG_SURFACE};
    font-weight: 700;
    font-size: 11px;
    letter-spacing: 0.8px;
    text-transform: uppercase;
    color: {TEXT_DIM};
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 6px;
    background-color: {BG_SURFACE};
    color: {ACCENT};
}}

/* ── Inputs ──────────────────────────────────────────────────────────────── */
QLineEdit, QSpinBox {{
    background-color: {BG_ELEVATED};
    color: {TEXT};
    border: 1px solid {BORDER};
    border-radius: 2px;
    padding: 6px 10px;
    selection-background-color: {ACCENT_DIM};
}}

QLineEdit:focus, QSpinBox:focus {{
    border-color: {ACCENT};
    background-color: {BG_ELEVATED};
    outline: none;
}}

QLineEdit::placeholder {{
    color: {TEXT_MUTED};
}}

QLineEdit:disabled, QSpinBox:disabled {{
    background-color: {BG_SURFACE};
    color: {TEXT_MUTED};
    border-color: {BORDER_SUB};
}}

QLineEdit[validationError="true"] {{
    border: 1px solid {RED};
    background-color: #200c0b;
}}

/* ── SpinBox buttons ─────────────────────────────────────────────────────── */
QSpinBox::up-button, QSpinBox::down-button {{
    background-color: {BG_ELEVATED};
    border: none;
    width: 18px;
}}

QSpinBox::up-button:hover, QSpinBox::down-button:hover {{
    background-color: {BORDER};
}}

/* ── ComboBox ────────────────────────────────────────────────────────────── */
QComboBox {{
    background-color: {BG_ELEVATED};
    color: {TEXT};
    border: 1px solid {BORDER};
    border-radius: 2px;
    padding: 6px 10px;
    min-width: 110px;
}}

QComboBox:focus {{
    border-color: {ACCENT};
}}

QComboBox:disabled {{
    background-color: {BG_SURFACE};
    color: {TEXT_MUTED};
    border-color: {BORDER_SUB};
}}

QComboBox::drop-down {{
    border: none;
    width: 22px;
    background-color: transparent;
}}

QComboBox::down-arrow {{
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid {TEXT_DIM};
    margin-right: 6px;
}}

QComboBox QAbstractItemView {{
    background-color: {BG_ELEVATED};
    color: {TEXT};
    border: 1px solid {BORDER};
    border-radius: 0px;
    selection-background-color: {ACCENT_DIM};
    outline: none;
}}

/* ── Buttons ─────────────────────────────────────────────────────────────── */
QPushButton {{
    background-color: {BG_ELEVATED};
    color: {TEXT_DIM};
    border: 1px solid {BORDER};
    border-radius: 2px;
    padding: 6px 16px;
    font-weight: 600;
}}

QPushButton:hover {{
    background-color: {BORDER};
    color: {TEXT};
    border-color: {ACCENT_DIM};
}}

QPushButton:pressed {{
    background-color: {ACCENT_DIM};
    color: {TEXT};
}}

QPushButton:disabled {{
    background-color: {BG_SURFACE};
    color: {TEXT_MUTED};
    border-color: {BORDER_SUB};
}}

/* BUILD button */
QPushButton#buildButton {{
    background-color: {ACCENT};
    color: {BG_BASE};
    border: none;
    padding: 11px 32px;
    font-size: 13px;
    font-weight: 700;
    border-radius: 2px;
    letter-spacing: 1.5px;
    text-transform: uppercase;
}}

QPushButton#buildButton:hover {{
    background-color: {ACCENT_BRIGHT};
}}

QPushButton#buildButton:pressed {{
    background-color: {ACCENT_DIM};
    color: {TEXT};
}}

QPushButton#buildButton:disabled {{
    background-color: {BG_ELEVATED};
    color: {TEXT_MUTED};
    border: 1px solid {BORDER_SUB};
}}

/* Browse button */
QPushButton#browseButton {{
    background-color: transparent;
    color: {ACCENT};
    border: 1px solid {ACCENT_DIM};
    padding: 6px 12px;
    border-radius: 2px;
    font-weight: 600;
}}

QPushButton#browseButton:hover {{
    background-color: {ACCENT_DIM};
    color: {TEXT};
    border-color: {ACCENT};
}}

/* Delete button */
QPushButton#deleteButton {{
    background-color: transparent;
    color: {RED};
    border: 1px solid #3d1a1a;
    padding: 6px 12px;
    border-radius: 2px;
    font-weight: 600;
}}

QPushButton#deleteButton:hover {{
    background-color: #2d1010;
    border-color: {RED};
}}

/* ── CheckBox ────────────────────────────────────────────────────────────── */
QCheckBox {{
    color: {TEXT_DIM};
    spacing: 8px;
    font-size: 12px;
}}

QCheckBox:hover {{
    color: {TEXT};
}}

QCheckBox::indicator {{
    width: 15px;
    height: 15px;
    border-radius: 2px;
    border: 1px solid {BORDER};
    background-color: {BG_ELEVATED};
}}

QCheckBox::indicator:checked {{
    background-color: {ACCENT};
    border-color: {ACCENT};
}}

QCheckBox::indicator:disabled {{
    background-color: {BG_SURFACE};
    border-color: {BORDER_SUB};
}}

/* ── Scroll area ─────────────────────────────────────────────────────────── */
QScrollArea {{
    border: none;
    background-color: {BG_BASE};
}}

QScrollBar:vertical {{
    background-color: {BG_BASE};
    width: 8px;
    border: none;
}}

QScrollBar::handle:vertical {{
    background-color: {BORDER};
    border-radius: 4px;
    min-height: 30px;
}}

QScrollBar::handle:vertical:hover {{
    background-color: {TEXT_MUTED};
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}

/* ── Splitter ────────────────────────────────────────────────────────────── */
QSplitter::handle {{
    background-color: {BORDER_SUB};
    height: 5px;
    border-top: 1px dotted {BORDER};
}}

QSplitter::handle:hover {{
    background-color: {ACCENT_DIM};
}}

/* ── Labels ──────────────────────────────────────────────────────────────── */
QLabel {{
    color: {TEXT};
    background: transparent;
}}

QLabel:disabled {{
    color: {TEXT_MUTED};
}}

QLabel#sectionLabel {{
    color: {TEXT_MUTED};
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}

QLabel#headerTitle {{
    font-size: 18px;
    font-weight: 800;
    color: {ACCENT};
    letter-spacing: 1px;
}}

QLabel#headerSubtitle {{
    font-size: 11px;
    color: {TEXT_DIM};
    letter-spacing: 0.3px;
}}

QLabel#headerBadge {{
    font-size: 9px;
    font-weight: 700;
    color: {BG_BASE};
    background-color: {ACCENT};
    padding: 2px 7px;
    border-radius: 2px;
    letter-spacing: 1px;
}}

/* ── Progress bar ────────────────────────────────────────────────────────── */
QProgressBar {{
    background-color: {BG_SURFACE};
    border: none;
    border-radius: 0px;
    height: 3px;
    text-align: center;
}}

QProgressBar::chunk {{
    background-color: {ACCENT};
    border-radius: 0px;
}}

/* ── Status bar ──────────────────────────────────────────────────────────── */
QStatusBar {{
    background-color: {BG_HEADER};
    color: {TEXT_MUTED};
    border-top: 1px solid {BORDER_SUB};
    font-size: 11px;
    font-family: "Cascadia Code", "Fira Code", "Consolas", monospace;
}}

QStatusBar QLabel {{
    color: {TEXT_DIM};
    padding: 2px 8px;
}}

/* ── Tooltip ─────────────────────────────────────────────────────────────── */
QToolTip {{
    background-color: {BG_ELEVATED};
    color: {TEXT};
    border: 1px solid {BORDER};
    border-radius: 2px;
    padding: 5px 9px;
    font-size: 12px;
}}

/* ── Horizontal scrollbar ────────────────────────────────────────────────── */
QScrollBar:horizontal {{
    background-color: {BG_BASE};
    height: 8px;
    border: none;
}}

QScrollBar::handle:horizontal {{
    background-color: {BORDER};
    border-radius: 4px;
    min-width: 30px;
}}

QScrollBar::handle:horizontal:hover {{
    background-color: {TEXT_MUTED};
}}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0px;
}}

/* ── Frame separators ────────────────────────────────────────────────────── */
QFrame[frameShape="4"], QFrame[frameShape="HLine"] {{
    background-color: {BORDER_SUB};
    border: none;
    max-height: 1px;
}}

/* ── Side nav (QListWidget#sideNav) ─────────────────────────────────────── */
QListWidget#sideNav {{
    background-color: {BG_SURFACE};
    border: none;
    outline: none;
    padding: 8px 0px;
    font-size: 12px;
}}

QListWidget#sideNav::item {{
    padding: 11px 0px 11px 18px;
    color: {TEXT_DIM};
    border-left: 3px solid transparent;
    font-weight: 600;
    letter-spacing: 0.3px;
}}

QListWidget#sideNav::item:selected {{
    background-color: {BG_ELEVATED};
    color: {ACCENT};
    border-left: 3px solid {ACCENT};
}}

QListWidget#sideNav::item:hover:!selected {{
    background-color: {BG_ELEVATED};
    color: {TEXT};
    border-left: 3px solid transparent;
}}

QListWidget#sideNav::item:disabled {{
    color: {TEXT_MUTED};
}}

/* ── Profiles bar + build footer ─────────────────────────────────────────── */
QWidget#profilesBar {{
    background-color: {BG_SURFACE};
    border-bottom: 1px solid {BORDER};
}}

QWidget#buildFooter {{
    background-color: {BG_SURFACE};
    border-top: 1px solid {BORDER};
}}

/* ── Dialogs (QMessageBox, QInputDialog, QFileDialog) ────────────────────── */
QDialog {{
    background-color: {BG_SURFACE};
    color: {TEXT};
    border: 1px solid {BORDER};
    min-width: 420px;
}}

QMessageBox {{
    background-color: {BG_SURFACE};
    color: {TEXT};
    min-width: 420px;
}}

QMessageBox QLabel {{
    color: {TEXT};
    font-size: 13px;
    padding: 4px 0px;
    min-width: 300px;
    background: transparent;
}}

/* Icon area spacer */
QMessageBox QDialogButtonBox {{
    padding-top: 8px;
}}

QInputDialog {{
    background-color: {BG_SURFACE};
    color: {TEXT};
    min-width: 380px;
}}

QInputDialog QLabel {{
    color: {TEXT};
    font-size: 13px;
    background: transparent;
}}

QInputDialog QLineEdit {{
    min-width: 300px;
}}

QFileDialog {{
    background-color: {BG_SURFACE};
    color: {TEXT};
}}

QFileDialog QLabel {{
    color: {TEXT};
    background: transparent;
}}

/* Buttons inside dialogs */
QDialogButtonBox QPushButton {{
    min-width: 80px;
    padding: 6px 18px;
}}
"""
