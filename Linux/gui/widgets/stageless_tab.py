# -*- coding: utf-8 -*-
"""Stageless payload configuration tab."""
import os
import json

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFormLayout, QLabel,
    QLineEdit, QComboBox, QCheckBox, QPushButton, QSpinBox,
    QScrollArea, QFrame, QListWidget, QStackedWidget,
    QListWidgetItem, QFileDialog
)
from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtGui import QKeySequence, QShortcut

from core.build_config import BuildConfig
from gui.theme import TEXT_DIM
from gui.widgets.common import file_picker_row, DropZone, dlg_ask, dlg_warn, dlg_error, dlg_info, dlg_text
from gui.history import HistoryManager

REQ = " *"


class StagelessTab(QWidget):
    """Form for stageless payload configuration."""

    build_requested  = pyqtSignal(object)  # emits BuildConfig
    profile_imported = pyqtSignal()        # emitted after a .ctfp import

    def __init__(self, history_manager: HistoryManager, parent=None):
        super().__init__(parent)
        self._history = history_manager
        self._setup_ui()
        self._setup_tooltips()
        self._setup_shortcuts()
        self._connect_adaptive()
        self._refresh_profiles()

    # ── Page indices ──────────────────────────────────────────────────────
    PAGE_PAYLOAD = 0
    PAGE_FORMAT  = 1
    PAGE_EVASION = 2
    PAGE_SIGNING = 3
    PAGE_OUTPUT  = 4

    def _setup_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # ── Top bar: Profiles ──────────────────────────────────────────────
        bar = QWidget()
        bar.setObjectName("profilesBar")
        bl = QHBoxLayout(bar)
        bl.setContentsMargins(12, 7, 12, 7)
        self._profile_combo = QComboBox()
        self._profile_combo.setMinimumWidth(180)
        self._profile_combo.currentTextChanged.connect(self._load_profile)
        self._save_btn = QPushButton("Save")
        self._save_btn.clicked.connect(self._save_profile)
        delete_btn = QPushButton("Delete")
        delete_btn.setObjectName("deleteButton")
        delete_btn.clicked.connect(self._delete_profile)
        export_btn = QPushButton("Export ↑")
        export_btn.setToolTip("Export selected profile to a .ctfp file")
        export_btn.clicked.connect(self._export_profile)
        import_btn = QPushButton("Import ↓")
        import_btn.setToolTip("Import a .ctfp profile file")
        import_btn.clicked.connect(self._import_profile)
        bl.addWidget(QLabel("Profile:"))
        bl.addWidget(self._profile_combo, stretch=1)
        bl.addWidget(self._save_btn)
        bl.addWidget(delete_btn)
        bl.addWidget(export_btn)
        bl.addWidget(import_btn)
        outer.addWidget(bar)

        # ── Body: sidebar + pages ──────────────────────────────────────────
        body = QWidget()
        body_layout = QHBoxLayout(body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)

        self._nav = QListWidget()
        self._nav.setObjectName("sideNav")
        self._nav.setFixedWidth(148)
        self._nav.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._nav.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        for name in ("Payload", "Format", "Evasion", "Code Signing", "Output"):
            self._nav.addItem(name)

        vdiv = QFrame()
        vdiv.setFrameShape(QFrame.Shape.VLine)
        vdiv.setFrameShadow(QFrame.Shadow.Plain)

        self._stack = QStackedWidget()
        self._stack.addWidget(self._page_payload())
        self._stack.addWidget(self._page_format())
        self._stack.addWidget(self._page_evasion())
        self._stack.addWidget(self._page_signing())
        self._stack.addWidget(self._page_output())

        self._nav.currentRowChanged.connect(self._stack.setCurrentIndex)
        self._nav.setCurrentRow(0)

        body_layout.addWidget(self._nav)
        body_layout.addWidget(vdiv)
        body_layout.addWidget(self._stack, stretch=1)
        outer.addWidget(body, stretch=1)

        # ── Bottom bar: BUILD + Reset ──────────────────────────────────────
        sep_bot = QFrame()
        sep_bot.setFrameShape(QFrame.Shape.HLine)
        sep_bot.setFrameShadow(QFrame.Shadow.Plain)
        outer.addWidget(sep_bot)

        footer = QWidget()
        footer.setObjectName("buildFooter")
        fl = QHBoxLayout(footer)
        fl.setContentsMargins(12, 8, 12, 8)
        self._build_btn = QPushButton("BUILD")
        self._build_btn.setObjectName("buildButton")
        self._build_btn.clicked.connect(self._on_build)
        self._reset_btn = QPushButton("Reset")
        self._reset_btn.setToolTip("Reset all fields to defaults")
        self._reset_btn.setFixedWidth(80)
        self._reset_btn.clicked.connect(self._reset_defaults)
        fl.addWidget(self._build_btn, stretch=1)
        fl.addWidget(self._reset_btn)
        outer.addWidget(footer)

    # ── Page helpers ───────────────────────────────────────────────────────

    def _make_page(self):
        """Scroll-wrapped page container. Returns (scroll_widget, layout)."""
        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(28, 22, 28, 22)
        layout.setSpacing(16)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(inner)
        return scroll, layout

    def _page_header(self, title: str, subtitle: str = "") -> QWidget:
        """Consistent page title + thin rule."""
        w = QWidget()
        vl = QVBoxLayout(w)
        vl.setContentsMargins(0, 0, 0, 6)
        vl.setSpacing(3)
        t = QLabel(title)
        t.setStyleSheet("font-size: 15px; font-weight: 700; color: #c9d1d9; background: transparent;")
        vl.addWidget(t)
        if subtitle:
            s = QLabel(subtitle)
            s.setStyleSheet(f"font-size: 11px; color: {TEXT_DIM}; background: transparent;")
            vl.addWidget(s)
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFrameShadow(QFrame.Shadow.Plain)
        vl.addWidget(line)
        return w

    # ── Pages ──────────────────────────────────────────────────────────────

    def _page_payload(self):
        page, layout = self._make_page()
        layout.addWidget(self._page_header("Payload", "Raw shellcode binary to embed in the loader"))
        self._payload_edit = DropZone(
            file_filter="Binary Files (*.bin);;All Files (*)",
            filter_exts=['.bin'],
            hint_text="Drag & drop shellcode (.bin) here",
            browse_title="Select Shellcode Binary",
            parent=self)
        self._payload_edit.path_changed.connect(
            lambda: self._clear_validation(self._payload_edit))
        layout.addWidget(self._payload_edit)
        layout.addStretch()
        return page

    def _page_format(self):
        page, layout = self._make_page()
        layout.addWidget(self._page_header("Output Format", "Loader type and injection technique"))

        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        form.setHorizontalSpacing(12)
        form.setVerticalSpacing(10)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.FieldsStayAtSizeHint)

        self._format_combo = QComboBox()
        self._format_combo.addItems(["EXE", "DLL"])
        self._format_combo.setMinimumWidth(140)
        form.addRow("Format:", self._format_combo)

        self._inject_combo = QComboBox()
        self._inject_combo.addItem("apc",                 "apc")
        self._inject_combo.addItem("copyfile2",           "copyfile2")
        self._inject_combo.addItem("Threadpool (TP_DIRECT)",    "tp_direct")
        self._inject_combo.addItem("Threadpool (WF Overwrite)", "wf_overwrite")
        self._inject_combo.addItem("Timer Queue (callback)",    "timerqueue")
        self._inject_combo.setMinimumWidth(140)
        form.addRow("Injection:", self._inject_combo)

        self._target_label = QLabel("Target process:")
        self._target_combo = QComboBox()
        self._target_combo.addItems(["RuntimeBroker.exe", "svchost.exe"])
        self._target_combo.setMinimumWidth(140)
        form.addRow(self._target_label, self._target_combo)

        layout.addLayout(form)
        layout.addStretch()
        return page

    def _page_evasion(self):
        page, layout = self._make_page()
        layout.addWidget(self._page_header("Evasion", "Loader-level detection avoidance techniques"))

        self._encrypt_check = QCheckBox("Encrypt shellcode (AES-128-CBC)")
        self._scramble_check = QCheckBox("Scramble functions and variables")
        self._unhook_check = QCheckBox("NTDLL unhooking (Known DLLs)")
        self._unhook_check.setChecked(True)
        self._entropy_check = QCheckBox("Entropy reduction (embed English text)")
        self._sandbox_check = QCheckBox("Sandbox checks")
        for check in (self._encrypt_check, self._scramble_check,
                      self._unhook_check, self._entropy_check, self._sandbox_check):
            layout.addWidget(check)

        self._sb_thresh_row = QWidget()
        thresh_layout = QHBoxLayout(self._sb_thresh_row)
        thresh_layout.setContentsMargins(22, 0, 0, 0)
        thresh_layout.setSpacing(5)
        self._sb_uptime_lbl = QLabel("uptime")
        self._sb_uptime_spin = QSpinBox()
        self._sb_uptime_spin.setRange(0, 86400)
        self._sb_uptime_spin.setSingleStep(60)
        self._sb_uptime_spin.setValue(300)
        self._sb_uptime_spin.setSuffix(" s")
        self._sb_uptime_spin.setFixedWidth(72)
        self._sb_uptime_spin.setToolTip("Min uptime (s) — sandboxes reboot per sample")
        self._sb_ram_lbl = QLabel("RAM")
        self._sb_ram_spin = QSpinBox()
        self._sb_ram_spin.setRange(1, 512)
        self._sb_ram_spin.setValue(4)
        self._sb_ram_spin.setSuffix(" GB")
        self._sb_ram_spin.setFixedWidth(76)
        self._sb_ram_spin.setToolTip("Min RAM (GB) — VMs are usually memory-constrained")
        self._sb_cpu_lbl = QLabel("CPUs")
        self._sb_cpu_spin = QSpinBox()
        self._sb_cpu_spin.setRange(1, 256)
        self._sb_cpu_spin.setValue(2)
        self._sb_cpu_spin.setSuffix(" CPU")
        self._sb_cpu_spin.setFixedWidth(76)
        self._sb_cpu_spin.setToolTip("Min CPU count — hypervisors often expose 1 vCPU")
        for lbl, spin in (
            (self._sb_uptime_lbl, self._sb_uptime_spin),
            (self._sb_ram_lbl, self._sb_ram_spin),
            (self._sb_cpu_lbl, self._sb_cpu_spin),
        ):
            thresh_layout.addWidget(lbl)
            thresh_layout.addWidget(spin)
            thresh_layout.addSpacing(12)
        thresh_layout.addStretch()
        self._sb_thresh_row.setVisible(False)
        self._sandbox_check.toggled.connect(self._sb_thresh_row.setVisible)
        layout.addWidget(self._sb_thresh_row)

        # ── Trampoline hooks (TrampoLatté) ───────────────────────────────
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFrameShadow(QFrame.Shadow.Plain)
        layout.addSpacing(6)
        layout.addWidget(sep)

        hooks_lbl = QLabel("AMSI & ETW (TrampoLatté)")
        hooks_lbl.setStyleSheet(
            f"color: {TEXT_DIM}; font-size: 10px; font-weight: 600; "
            "letter-spacing: 0.6px; text-transform: uppercase; "
            "background: transparent; border: none;")
        layout.addWidget(hooks_lbl)

        self._amsi_check = QCheckBox("AMSI bypass")
        self._amsi_check.setToolTip(
            "Trampolines AmsiScanBuffer → always AMSI_RESULT_CLEAN.\n"
            "Bypasses .NET / PowerShell AMSI scanning.")
        self._etw_check = QCheckBox("ETW bypass")
        self._etw_check.setToolTip(
            "Trampolines EtwpEventWriteFull → immediate RET.\n"
            "Silences ETW telemetry from the CLR / runtime.")
        self._debug_check = QCheckBox("Debug mode (OutputDebugString)")
        self._debug_check.setToolTip(
            "Enables [TrampoLatte] debug prints via OutputDebugStringA.\n"
            "Visible in x64dbg / WinDbg / DebugView. Disable for production.")
        layout.addWidget(self._amsi_check)
        layout.addWidget(self._etw_check)
        layout.addWidget(self._debug_check)

        layout.addStretch()
        return page

    def _page_signing(self):
        page, layout = self._make_page()
        layout.addWidget(self._page_header("Code Signing", "Sign the loader with an Authenticode certificate"))

        self._pfx_edit = DropZone(
            hint_text="Drag & drop certificate (.pfx) here",
            browse_title="Select PFX certificate",
            file_filter="PFX Files (*.pfx);;All Files (*)",
            filter_exts=[".pfx"],
            parent=self)
        layout.addWidget(self._pfx_edit)

        form_sign = QFormLayout()
        form_sign.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        form_sign.setHorizontalSpacing(12)
        form_sign.setVerticalSpacing(10)
        form_sign.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)

        self._pfx_pass_edit = QLineEdit()
        self._pfx_pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        form_sign.addRow("PFX Password:", self._pfx_pass_edit)
        layout.addLayout(form_sign)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFrameShadow(QFrame.Shadow.Plain)
        layout.addSpacing(4)
        layout.addWidget(sep)

        meta_label = QLabel("Signature Metadata")
        meta_label.setStyleSheet(
            f"color: {TEXT_DIM}; font-size: 10px; font-weight: 600; "
            "letter-spacing: 0.6px; text-transform: uppercase; background: transparent; border: none;")
        layout.addWidget(meta_label)

        form_meta = QFormLayout()
        form_meta.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        form_meta.setHorizontalSpacing(12)
        form_meta.setVerticalSpacing(10)
        form_meta.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)

        self._sign_desc_edit = QLineEdit()
        self._sign_desc_edit.setPlaceholderText("Authenticode program name (blank = default)")
        self._sign_desc_edit.setToolTip("Sets -n in osslsigncode. Appears in Windows signature details.")
        form_meta.addRow("Publisher Name:", self._sign_desc_edit)

        self._sign_url_edit = QLineEdit()
        self._sign_url_edit.setPlaceholderText("Authenticode program URL (blank = default)")
        self._sign_url_edit.setToolTip("Sets -i in osslsigncode. Appears in Windows signature details.")
        form_meta.addRow("Publisher URL:", self._sign_url_edit)

        layout.addLayout(form_meta)
        layout.addStretch()
        return page

    def _page_output(self):
        page, layout = self._make_page()
        layout.addWidget(self._page_header("Output", "Output file path and base name"))
        out_row, self._output_edit = file_picker_row(
            self, "Output base name (e.g. ctfloader)", "All Files (*)", save_mode=True)
        layout.addLayout(out_row)
        layout.addStretch()
        return page

    def _setup_tooltips(self):
        self._payload_edit.setToolTip("Path to raw shellcode .bin file (drag & drop supported)")
        self._format_combo.setToolTip("EXE: standalone executable | DLL: dynamic library for injection")
        self._inject_combo.setToolTip(
            "apc: EarlyBird APC into suspended process\n"
            "copyfile2: CopyFile2 progress callback (self-injection)\n"
            "Threadpool (TP_DIRECT): PoolParty — ZwSetIoCompletion via IoCompletion handle (existing process)\n"
            "Threadpool (WF Overwrite): PoolParty — overwrite WorkerFactory StartRoutine (existing process)\n"
            "Timer Queue (callback): CreateTimerQueueTimer self-injection — shellcode runs on thread pool (current process)")
        self._target_combo.setToolTip("Process to inject into via APC (only used with APC injection)")
        self._encrypt_check.setToolTip("Encrypt shellcode with AES-128-CBC (key/IV embedded in loader)")
        self._scramble_check.setToolTip("Randomize function/variable names and optimization level for polymorphism")
        self._unhook_check.setToolTip("Remap a clean copy of NTDLL from KnownDlls, removing any userland hooks set by AV/EDR")
        self._entropy_check.setToolTip("Embed English text in loader to reduce entropy")
        self._sandbox_check.setToolTip("Check uptime, RAM, and CPU count before executing — exits cleanly if a sandbox is detected")
        self._pfx_edit.setToolTip("PFX certificate file for code signing (EXE only, drag & drop supported)")
        self._pfx_pass_edit.setToolTip("Password for the PFX certificate file")
        self._output_edit.setToolTip("Base name for output files (e.g. 'loader' produces loader.exe/.dll)")
        self._build_btn.setToolTip("Start the build (Ctrl+B)")
        self._save_btn.setToolTip("Save current settings as a profile (Ctrl+S)")

    def _setup_shortcuts(self):
        QShortcut(QKeySequence("Ctrl+B"), self, self._on_build)
        QShortcut(QKeySequence("Ctrl+S"), self, self._save_profile)

    def _connect_adaptive(self):
        self._inject_combo.currentIndexChanged.connect(lambda _: self._on_inject_changed(self._inject_combo.currentData()))
        self._format_combo.currentTextChanged.connect(self._on_format_changed)
        self._on_inject_changed(self._inject_combo.currentData())
        self._on_format_changed(self._format_combo.currentText())

    def _on_inject_changed(self, method: str):
        is_apc = method == "apc"
        self._target_label.setVisible(is_apc)
        self._target_combo.setVisible(is_apc)

    def _on_format_changed(self, fmt: str):
        is_exe = fmt == "EXE"
        item = self._nav.item(self.PAGE_SIGNING)
        if is_exe:
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
        else:
            item.setFlags(item.flags() & ~(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable))
            if self._nav.currentRow() == self.PAGE_SIGNING:
                self._nav.setCurrentRow(self.PAGE_OUTPUT)

    def set_build_enabled(self, enabled: bool):
        self._build_btn.setEnabled(enabled)
        if enabled:
            self._build_btn.setText("BUILD")
        else:
            self._build_btn.setText("BUILDING...")

    def _validate(self) -> bool:
        errors = []

        payload = self._payload_edit.text().strip()
        if not payload:
            self._set_validation_error(self._payload_edit)
            errors.append("Payload file")
        elif not os.path.isfile(payload):
            self._set_validation_error(self._payload_edit)
            errors.append(f"Payload file not found: {payload}")

        if errors:
            dlg_warn(self, "Missing Required Fields",
                     f"Please fill in: {', '.join(errors)}")
            return False
        return True

    @staticmethod
    def _set_validation_error(widget):
        widget.setProperty("validationError", True)
        widget.style().unpolish(widget)
        widget.style().polish(widget)

    @staticmethod
    def _clear_validation(widget):
        if widget.property("validationError"):
            widget.setProperty("validationError", False)
            widget.style().unpolish(widget)
            widget.style().polish(widget)

    def _on_build(self):
        if not self._build_btn.isEnabled():
            return
        if not self._validate():
            return

        config = BuildConfig(
            mode="stageless",
            payload_path=self._payload_edit.text(),
            format=self._format_combo.currentText(),
            inject_method=self._inject_combo.currentData(),
            target_process=self._target_combo.currentText(),
            encrypt=self._encrypt_check.isChecked(),
            scramble=self._scramble_check.isChecked(),
            unhook=self._unhook_check.isChecked(),
            entropy_reduction=self._entropy_check.isChecked(),
            sandbox_checks=self._sandbox_check.isChecked(),
            sandbox_min_uptime_s=self._sb_uptime_spin.value(),
            sandbox_min_ram_gb=self._sb_ram_spin.value(),
            sandbox_min_cpu=self._sb_cpu_spin.value(),
            bypass_amsi=self._amsi_check.isChecked(),
            bypass_etw=self._etw_check.isChecked(),
            debug_mode=self._debug_check.isChecked(),
            pfx=self._pfx_edit.text() or None,
            pfx_password=self._pfx_pass_edit.text() or None,
            sign_description=self._sign_desc_edit.text().strip(),
            sign_url=self._sign_url_edit.text().strip(),
            output=self._output_edit.text() or "ctfloader",
        )
        self.build_requested.emit(config)

    def _apply_config(self, config: BuildConfig):
        self._payload_edit.setText(config.payload_path)
        self._format_combo.setCurrentText(config.format)
        self._inject_combo.setCurrentIndex(next((i for i in range(self._inject_combo.count()) if self._inject_combo.itemData(i) == config.inject_method), 0))
        self._target_combo.setCurrentText(config.target_process)
        self._encrypt_check.setChecked(config.encrypt)
        self._scramble_check.setChecked(config.scramble)
        self._unhook_check.setChecked(getattr(config, 'unhook', True))
        self._entropy_check.setChecked(getattr(config, 'entropy_reduction', False))
        self._sandbox_check.setChecked(getattr(config, 'sandbox_checks', False))
        self._sb_uptime_spin.setValue(getattr(config, 'sandbox_min_uptime_s', 300))
        self._sb_ram_spin.setValue(getattr(config, 'sandbox_min_ram_gb', 4))
        self._sb_cpu_spin.setValue(getattr(config, 'sandbox_min_cpu', 2))
        self._amsi_check.setChecked(getattr(config, 'bypass_amsi', False))
        self._etw_check.setChecked(getattr(config, 'bypass_etw', False))
        self._debug_check.setChecked(getattr(config, 'debug_mode', False))
        self._pfx_edit.setText(config.pfx or "")
        self._pfx_pass_edit.setText("")  # never restored — password is not persisted
        self._sign_desc_edit.setText(getattr(config, 'sign_description', '') or "")
        self._sign_url_edit.setText(getattr(config, 'sign_url', '') or "")
        self._output_edit.setText(config.output)

    def _reset_defaults(self):
        """Reset all fields to BuildConfig defaults."""
        self._apply_config(BuildConfig(mode="stageless"))
        self._profile_combo.setCurrentIndex(0)

    # -- Profile management --

    def _refresh_profiles(self):
        self._profile_combo.blockSignals(True)
        self._profile_combo.clear()
        self._profile_combo.addItem("")
        for name in self._history.list_profiles("stageless"):
            self._profile_combo.addItem(name)
        self._profile_combo.blockSignals(False)

    def _load_profile(self, name: str):
        if not name:
            return
        config = self._history.load_profile("stageless", name)
        if config:
            self._apply_config(config)

    def _save_profile(self):
        name = self._profile_combo.currentText().strip()
        if not name:
            name, ok = dlg_text(self, "Save Profile", "Profile name:")
            if not ok or not name.strip():
                return
            name = name.strip()

        config = BuildConfig(
            mode="stageless",
            payload_path=self._payload_edit.text(),
            format=self._format_combo.currentText(),
            inject_method=self._inject_combo.currentData(),
            target_process=self._target_combo.currentText(),
            encrypt=self._encrypt_check.isChecked(),
            scramble=self._scramble_check.isChecked(),
            unhook=self._unhook_check.isChecked(),
            entropy_reduction=self._entropy_check.isChecked(),
            sandbox_checks=self._sandbox_check.isChecked(),
            sandbox_min_uptime_s=self._sb_uptime_spin.value(),
            sandbox_min_ram_gb=self._sb_ram_spin.value(),
            sandbox_min_cpu=self._sb_cpu_spin.value(),
            bypass_amsi=self._amsi_check.isChecked(),
            bypass_etw=self._etw_check.isChecked(),
            debug_mode=self._debug_check.isChecked(),
            pfx=self._pfx_edit.text() or None,
            pfx_password=self._pfx_pass_edit.text() or None,
            sign_description=self._sign_desc_edit.text().strip(),
            sign_url=self._sign_url_edit.text().strip(),
            output=self._output_edit.text() or "ctfloader",
        )
        self._history.save_profile("stageless", name, config)
        self._refresh_profiles()
        self._profile_combo.setCurrentText(name)

    def _delete_profile(self):
        name = self._profile_combo.currentText().strip()
        if not name:
            return
        if dlg_ask(self, "Delete Profile", f"Delete profile '{name}'?"):
            self._history.delete_profile("stageless", name)
            self._refresh_profiles()

    def _export_profile(self):
        name = self._profile_combo.currentText().strip()
        if not name:
            dlg_warn(self, "No Profile Selected",
                     "Select a saved profile before exporting.")
            return
        try:
            data = self._history.export_profile("stageless", name)
        except KeyError:
            dlg_warn(self, "Export Failed",
                     f"Profile '{name}' could not be found.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Profile", f"{name}.ctfp",
            "CTFPacker Profile (*.ctfp);;All Files (*)")
        if not path:
            return
        try:
            with open(path, "w") as fh:
                json.dump(data, fh, indent=2)
        except IOError as exc:
            dlg_error(self, "Export Failed", f"Could not write file:\n{exc}")

    def _import_profile(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Import Profile", "",
            "CTFPacker Profile (*.ctfp);;All Files (*)")
        if not path:
            return
        try:
            with open(path, "r") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, IOError) as exc:
            dlg_error(self, "Import Failed",
                      f"Could not read profile file:\n{exc}")
            return

        profile_mode = data.get("mode", "")
        profile_name = data.get("name", "").strip()

        if profile_mode not in ("staged", "stageless"):
            dlg_error(self, "Import Failed",
                      "Invalid profile file: unknown mode.")
            return

        if profile_mode != "stageless":
            if not dlg_ask(self, "Mode Mismatch",
                           f"This profile is for the <b>{profile_mode}</b> tab, "
                           f"not stageless.\nIt will be imported into the "
                           f"<b>{profile_mode}</b> profile list.\n\nContinue?",
                           default_yes=True):
                return

        if profile_name in self._history.list_profiles(profile_mode):
            if not dlg_ask(self, "Profile Exists",
                           f"A profile named '{profile_name}' already exists "
                           f"in the {profile_mode} tab.\nOverwrite?"):
                return

        try:
            mode, name = self._history.import_profile(data)
        except ValueError as exc:
            dlg_error(self, "Import Failed", str(exc))
            return

        self.profile_imported.emit()
        if mode == "stageless":
            self._profile_combo.setCurrentText(name)
        else:
            dlg_info(self, "Profile Imported",
                     f"Profile '{name}' imported into the {mode} tab.")
