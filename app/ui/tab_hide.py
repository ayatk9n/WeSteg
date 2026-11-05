# WeSteg - Hide & Embed Studio View

import os
from typing import Callable, List, Optional, Tuple
from PIL import Image
from PyQt6.QtCore import QObject, QRunnable, Qt, QThreadPool, pyqtSignal
from PyQt6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QRadioButton,
    QSpinBox,
    QSplitter,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from app.core.encoders_cli import (
    embed_with_openstego,
    embed_with_outguess,
    embed_with_steghide,
)
from app.core.encoders_lsb import (
    calculate_lsb_capacity,
    embed_lsb_data,
    stamp_visual_text_on_bitplane,
)
from app.core.encoders_meta import (
    append_eof_payload,
    inject_exif_metadata,
    inject_png_chunk,
)
from app.ui.widgets import pil_to_thumbnail_qpixmap


class EmbedWorkerSignals(QObject):
    finished = pyqtSignal(bool, str, str, str)


class EmbedTask(QRunnable):
    def __init__(
        self,
        fn: Callable[[], Tuple[bool, str, str]],
        error_title: str,
        signals: EmbedWorkerSignals,
    ):
        super().__init__()
        self.fn = fn
        self.error_title = error_title
        self.signals = signals

    def run(self):
        try:
            ok, out_path, msg = self.fn()
        except Exception as exc:
            ok, out_path, msg = False, "", str(exc)
        try:
            self.signals.finished.emit(ok, out_path, msg, self.error_title)
        except RuntimeError:
            pass


def _ensure_extension(path: str, selected_filter: str, fallback_ext: str) -> str:
    if os.path.splitext(path)[1]:
        return path
    if "*.bmp" in selected_filter.lower():
        return path + ".bmp"
    if "*.png" in selected_filter.lower():
        return path + ".png"
    return path + (fallback_ext if fallback_ext.startswith(".") else f".{fallback_ext}")


class HideStudioTab(QWidget):

    analyze_created_file_signal = pyqtSignal(str)
    status_signal = pyqtSignal(str)

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.cover_file_path: str = ""
        self.payload_file_path: str = ""
        self.last_output_path: str = ""
        self.thread_pool = QThreadPool.globalInstance()
        self._action_buttons: List[QPushButton] = []

        self.embed_signals = EmbedWorkerSignals(self)
        self.embed_signals.finished.connect(self._on_embed_finished)

        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        top_splitter = QSplitter(Qt.Orientation.Horizontal)

        cover_box = QGroupBox("1. Cover Image / Carrier File")
        cb_layout = QVBoxLayout(cover_box)

        btn_row = QHBoxLayout()
        self.btn_select_cover = QPushButton("Select Cover File...")
        self.btn_select_cover.setObjectName("PrimaryPill")
        self.btn_select_cover.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_select_cover.clicked.connect(self.browse_cover)
        btn_row.addWidget(self.btn_select_cover)

        self.lbl_cover_info = QLabel("No cover file selected")
        self.lbl_cover_info.setStyleSheet("color: #5a6a7a; background: transparent;")
        btn_row.addWidget(self.lbl_cover_info, stretch=1)
        cb_layout.addLayout(btn_row)

        self.lbl_cover_preview = QLabel("Cover Preview")
        self.lbl_cover_preview.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_cover_preview.setFixedHeight(145)
        self.lbl_cover_preview.setStyleSheet(
            "background-color: #dde5ed; color: #5a6a7a; font-weight: bold; "
            "border: 2px solid #c2cedb; border-radius: 12px;"
        )
        cb_layout.addWidget(self.lbl_cover_preview)

        top_splitter.addWidget(cover_box)

        payload_box = QGroupBox("2. Secret Payload to Hide (Text Message or Any Binary File)")
        pb_layout = QVBoxLayout(payload_box)

        mode_row = QHBoxLayout()
        self.radio_text = QRadioButton("Secret Text / Flag")
        self.radio_file = QRadioButton("Secret File (.zip, .pdf, .png, .txt, etc.)")
        self.radio_text.setStyleSheet("background: transparent; font-weight: bold;")
        self.radio_file.setStyleSheet("background: transparent; font-weight: bold;")
        self.radio_text.setChecked(True)
        self.payload_group = QButtonGroup(self)
        self.payload_group.addButton(self.radio_text)
        self.payload_group.addButton(self.radio_file)
        self.radio_text.toggled.connect(self._on_payload_source_toggled)
        mode_row.addWidget(self.radio_text)
        mode_row.addWidget(self.radio_file)
        mode_row.addStretch()

        self.lbl_payload_size = QLabel("Payload Size: 0 B")
        self.lbl_payload_size.setStyleSheet("color: #086494; font-weight: bold; background: transparent;")
        mode_row.addWidget(self.lbl_payload_size)
        pb_layout.addLayout(mode_row)

        self.txt_payload = QPlainTextEdit()
        self.txt_payload.setPlaceholderText("Enter secret message, CTF flag (e.g. CTF{h1dd3n_1n_pl41n_s1ght}), or notes...")
        self.txt_payload.setFixedHeight(95)
        self.txt_payload.textChanged.connect(self._update_capacity_labels)
        pb_layout.addWidget(self.txt_payload)

        self.file_payload_widget = QWidget()
        self.file_payload_widget.setStyleSheet("background: transparent;")
        fp_layout = QHBoxLayout(self.file_payload_widget)
        fp_layout.setContentsMargins(0, 0, 0, 0)
        self.btn_select_payload_file = QPushButton("Choose Secret File to Embed...")
        self.btn_select_payload_file.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_select_payload_file.clicked.connect(self.browse_payload_file)
        fp_layout.addWidget(self.btn_select_payload_file)
        self.lbl_payload_file = QLabel("No secret file chosen")
        self.lbl_payload_file.setStyleSheet("color: #5a6a7a; background: transparent;")
        fp_layout.addWidget(self.lbl_payload_file, stretch=1)
        self.file_payload_widget.setVisible(False)
        pb_layout.addWidget(self.file_payload_widget)

        top_splitter.addWidget(payload_box)
        top_splitter.setSizes([450, 650])
        root.addWidget(top_splitter)

        self.method_tabs = QTabWidget()
        self.method_tabs.addTab(self._build_lsb_subtab(), "1. LSB & Bit-Plane Encoder (PNG/BMP)")
        self.method_tabs.addTab(self._build_cli_subtab(), "2. Password Stego (Steghide / OutGuess / OpenStego)")
        self.method_tabs.addTab(self._build_meta_subtab(), "3. Metadata, PNG Chunks & EOF Polyglots")
        root.addWidget(self.method_tabs, stretch=1)

        bottom_bar = QFrame()
        bottom_bar.setObjectName("ControlDeckBar")
        bb_layout = QHBoxLayout(bottom_bar)
        bb_layout.setContentsMargins(10, 6, 10, 6)
        self.lbl_status = QLabel("Ready to embed hidden data.")
        self.lbl_status.setStyleSheet("color: #3a4856; font-size: 12px; font-weight: bold; background: transparent;")
        bb_layout.addWidget(self.lbl_status, stretch=1)

        self.btn_send_to_analyze = QPushButton("Verify & Inspect Last Output in Analyzer")
        self.btn_send_to_analyze.setObjectName("PrimaryPill")
        self.btn_send_to_analyze.setEnabled(False)
        self.btn_send_to_analyze.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_send_to_analyze.clicked.connect(self._send_last_output_to_analyzer)
        bb_layout.addWidget(self.btn_send_to_analyze)

        root.addWidget(bottom_bar)

    def _build_lsb_subtab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(12)

        form = QFormLayout()

        ch_row = QHBoxLayout()
        self.chk_ch_r = QCheckBox("Red (R)")
        self.chk_ch_g = QCheckBox("Green (G)")
        self.chk_ch_b = QCheckBox("Blue (B)")
        self.chk_ch_a = QCheckBox("Alpha (A)")
        for chk in (self.chk_ch_r, self.chk_ch_g, self.chk_ch_b):
            chk.setChecked(True)
        for chk in (self.chk_ch_r, self.chk_ch_g, self.chk_ch_b, self.chk_ch_a):
            chk.stateChanged.connect(self._update_capacity_labels)
            ch_row.addWidget(chk)
        ch_row.addStretch()
        form.addRow("Target Color Channels:", ch_row)

        bit_row = QHBoxLayout()
        self.chk_bits: List[QCheckBox] = []
        for b in range(8):
            chk = QCheckBox(f"Bit {b}" + (" (LSB)" if b == 0 else ""))
            if b == 0:
                chk.setChecked(True)
            chk.stateChanged.connect(self._update_capacity_labels)
            self.chk_bits.append(chk)
            bit_row.addWidget(chk)
        bit_row.addStretch()
        form.addRow("Target Bit Planes:", bit_row)

        self.combo_lsb_mode = QComboBox()
        self.combo_lsb_mode.addItems(
            [
                "Raw Bitstream (zsteg-compatible / directly visible in LSB strings)",
                "WeSteg Framed File (Lossless filename + length header for binary files)",
                "AES-256-GCM Encrypted (PBKDF2-SHA256 passphrase encrypted before LSB embedding)",
                "Visual Bit-Plane Text Stamp (Draws readable graphical text onto a single bit plane)",
            ]
        )
        self.combo_lsb_mode.currentIndexChanged.connect(self._update_capacity_labels)
        form.addRow("LSB Encoding Mode:", self.combo_lsb_mode)

        self.input_lsb_pass = QLineEdit()
        self.input_lsb_pass.setPlaceholderText("Passphrase (used when AES-256-GCM Encrypted mode is selected)...")
        form.addRow("AES-256 Passphrase:", self.input_lsb_pass)

        self.lbl_lsb_capacity = QLabel("Available LSB Capacity: Select a PNG or BMP cover image")
        self.lbl_lsb_capacity.setStyleSheet("color: #15803d; font-weight: bold; background: transparent;")
        form.addRow("Capacity Calculator:", self.lbl_lsb_capacity)

        layout.addLayout(form)
        layout.addStretch()

        btn_embed_lsb = QPushButton("Generate LSB Stego Image (Save As PNG/BMP)...")
        btn_embed_lsb.setObjectName("PrimaryPill")
        btn_embed_lsb.setMinimumHeight(40)
        btn_embed_lsb.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_embed_lsb.clicked.connect(self.execute_lsb_embed)
        self._action_buttons.append(btn_embed_lsb)
        layout.addWidget(btn_embed_lsb)

        return w

    def _build_cli_subtab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(12)

        form = QFormLayout()

        self.combo_cli_tool = QComboBox()
        self.combo_cli_tool.addItems(
            [
                "Steghide (Supports JPEG, BMP, WAV, AU cover files)",
                "OutGuess (Supports JPEG, PPM, PNM cover files)",
                "OpenStego (Supports PNG, BMP cover files)",
            ]
        )
        form.addRow("Steganography CLI Tool:", self.combo_cli_tool)

        self.input_cli_pass = QLineEdit()
        self.input_cli_pass.setPlaceholderText("Enter passphrase to encrypt and hide payload...")
        form.addRow("Encryption Passphrase:", self.input_cli_pass)

        self.spin_steghide_comp = QSpinBox()
        self.spin_steghide_comp.setRange(1, 9)
        self.spin_steghide_comp.setValue(9)
        form.addRow("Compression Level (1-9):", self.spin_steghide_comp)

        info_lbl = QLabel(
            "Tip: Steghide is the standard tool for hiding files inside JPEG/BMP/WAV with a passphrase.\n"
            "You can test extracting or cracking your generated file immediately in the Analyze tab."
        )
        info_lbl.setStyleSheet("color: #5a6a7a; background: transparent;")
        form.addRow("Notes:", info_lbl)

        layout.addLayout(form)
        layout.addStretch()

        btn_embed_cli = QPushButton("Embed Payload with Selected CLI Tool...")
        btn_embed_cli.setObjectName("PrimaryPill")
        btn_embed_cli.setMinimumHeight(40)
        btn_embed_cli.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_embed_cli.clicked.connect(self.execute_cli_embed)
        self._action_buttons.append(btn_embed_cli)
        layout.addWidget(btn_embed_cli)

        return w

    def _build_meta_subtab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        self.combo_meta_technique = QComboBox()
        self.combo_meta_technique.addItems(
            [
                "1. EOF File Appender / Polyglot Builder (Append secret file/ZIP/text past IEND or JPEG EOI)",
                "2. PNG Custom Chunk Injector (Inject tEXt, zTXt zlib-compressed, or custom 4-byte chunk before IEND)",
                "3. EXIF / Metadata Tag Injector (Write payload into Artist, UserComment, Copyright, ImageDescription)",
            ]
        )
        layout.addWidget(QLabel("Select Injection Technique:"))
        layout.addWidget(self.combo_meta_technique)

        form = QFormLayout()

        self.combo_png_chunk = QComboBox()
        self.combo_png_chunk.setEditable(True)
        self.combo_png_chunk.addItems(["tEXt", "zTXt", "sEcR", "fLaG", "cTfX"])
        form.addRow("PNG Chunk Type (4 ASCII letters):", self.combo_png_chunk)

        self.input_png_keyword = QLineEdit("Comment")
        self.input_png_keyword.setPlaceholderText("Keyword for tEXt/zTXt chunk (e.g. Comment, Author, Flag)...")
        form.addRow("PNG Chunk Keyword:", self.input_png_keyword)

        self.input_exif_artist = QLineEdit()
        self.input_exif_artist.setPlaceholderText("Optional Artist tag value...")
        form.addRow("EXIF Artist Tag:", self.input_exif_artist)

        self.input_exif_copyright = QLineEdit()
        self.input_exif_copyright.setPlaceholderText("Optional Copyright tag value...")
        form.addRow("EXIF Copyright Tag:", self.input_exif_copyright)

        layout.addLayout(form)
        layout.addStretch()

        btn_embed_meta = QPushButton("Inject Metadata / Chunk / EOF Payload...")
        btn_embed_meta.setObjectName("PrimaryPill")
        btn_embed_meta.setMinimumHeight(40)
        btn_embed_meta.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_embed_meta.clicked.connect(self.execute_meta_embed)
        self._action_buttons.append(btn_embed_meta)
        layout.addWidget(btn_embed_meta)

        return w

    def _on_payload_source_toggled(self):
        is_text = self.radio_text.isChecked()
        self.txt_payload.setVisible(is_text)
        self.file_payload_widget.setVisible(not is_text)
        self._update_capacity_labels()

    def browse_cover(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Cover Image or Media File",
            "",
            "Images & Media (*.png *.jpg *.jpeg *.bmp *.gif *.webp *.wav *.au);;All Files (*)",
        )
        if not path:
            return
        self.cover_file_path = path
        sz = os.path.getsize(path)
        try:
            with Image.open(path) as img:
                self.lbl_cover_info.setText(f"{os.path.basename(path)} ({img.width}x{img.height} {img.mode}, {sz:,} B)")
                pix = pil_to_thumbnail_qpixmap(img, 240, 135, smooth=True)
            self.lbl_cover_preview.setPixmap(pix)
        except Exception:
            self.lbl_cover_info.setText(f"{os.path.basename(path)} ({sz:,} B)")
            self.lbl_cover_preview.clear()
            self.lbl_cover_preview.setText(os.path.basename(path))

        self._update_capacity_labels()

    def browse_payload_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Secret File to Hide", "", "All Files (*)")
        if path:
            self.payload_file_path = path
            sz = os.path.getsize(path)
            self.lbl_payload_file.setText(f"{os.path.basename(path)} ({sz:,} bytes)")
            self._update_capacity_labels()

    def _get_payload_size_and_name_fast(self) -> Tuple[int, str]:
        if self.radio_text.isChecked():
            return len(self.txt_payload.toPlainText().encode("utf-8")), "secret_message.txt"
        if self.payload_file_path and os.path.isfile(self.payload_file_path):
            return os.path.getsize(self.payload_file_path), os.path.basename(self.payload_file_path)
        return 0, "secret.bin"

    def _get_payload_bytes_and_name(self) -> Tuple[bytes, str]:
        if self.radio_text.isChecked():
            txt = self.txt_payload.toPlainText()
            return (txt.encode("utf-8"), "secret_message.txt")
        if not self.payload_file_path or not os.path.isfile(self.payload_file_path):
            raise ValueError("Please select a secret file to embed first.")
        with open(self.payload_file_path, "rb") as f:
            return (f.read(), os.path.basename(self.payload_file_path))

    def _get_selected_channels_and_bits(self) -> Tuple[List[str], List[int]]:
        channels = []
        if self.chk_ch_r.isChecked():
            channels.append("R")
        if self.chk_ch_g.isChecked():
            channels.append("G")
        if self.chk_ch_b.isChecked():
            channels.append("B")
        if self.chk_ch_a.isChecked():
            channels.append("A")
        bits = [i for i, chk in enumerate(self.chk_bits) if chk.isChecked()]
        return channels, bits

    def _update_capacity_labels(self):
        plen, fname = self._get_payload_size_and_name_fast()
        self.lbl_payload_size.setText(f"Payload Size: {plen:,} bytes")

        if self.cover_file_path and os.path.isfile(self.cover_file_path):
            mode_idx = self.combo_lsb_mode.currentIndex()
            if mode_idx == 3:
                self.lbl_lsb_capacity.setStyleSheet("color: #086494; font-weight: bold; background: transparent;")
                self.lbl_lsb_capacity.setText("Visual Stamp Mode: Renders graphical text onto first selected channel/bit")
                return
            try:
                channels, bits = self._get_selected_channels_and_bits()
                mode_key = {0: "raw_zsteg", 1: "framed", 2: "aes_gcm"}.get(mode_idx, "raw_zsteg")
                cap = calculate_lsb_capacity(
                    self.cover_file_path,
                    channels,
                    bits,
                    mode=mode_key,
                    filename=fname,
                )
                pct = (plen / max(1, cap.usable_bytes)) * 100 if cap.usable_bytes > 0 else 100.0
                fits = cap.usable_bytes > 0 and plen <= cap.usable_bytes
                color = "#15803d" if fits else "#dc2626"
                self.lbl_lsb_capacity.setStyleSheet(f"color: {color}; font-weight: bold; background: transparent;")
                self.lbl_lsb_capacity.setText(
                    f"Usable Capacity: {cap.usable_bytes:,} bytes ({cap.width}x{cap.height} px, "
                    f"{cap.channels_count} ch x {cap.bits_per_channel} bit) - Payload: {plen:,} B ({pct:.1f}%)"
                )
            except Exception:
                self.lbl_lsb_capacity.setText("Cover is non-image or capacity N/A")

    def _run_async_embed(self, worker_fn: Callable[[], Tuple[bool, str, str]], error_title: str):
        for btn in self._action_buttons:
            btn.setEnabled(False)
        self.lbl_status.setText("Embedding payload in background...")
        self.lbl_status.setStyleSheet("color: #086494; font-weight: bold; font-size: 12px; background: transparent;")
        self.status_signal.emit("Embedding payload...")
        task = EmbedTask(worker_fn, error_title, self.embed_signals)
        self.thread_pool.start(task)

    def _on_embed_finished(self, ok: bool, out_path: str, msg: str, error_title: str):
        for btn in self._action_buttons:
            btn.setEnabled(True)
        if ok:
            self.last_output_path = out_path
            self.lbl_status.setText(f"[OK] {msg} -> {out_path}")
            self.lbl_status.setStyleSheet("color: #15803d; font-weight: bold; font-size: 12px; background: transparent;")
            self.status_signal.emit(f"Saved {os.path.basename(out_path)}")
            self.btn_send_to_analyze.setEnabled(True)
            QMessageBox.information(
                self,
                "Steganography Output Created",
                f"{msg}\n\nSaved to:\n{out_path}\n\n"
                "Click 'Verify & Inspect Last Output in Analyzer' at the bottom right to immediately test extraction.",
            )
        else:
            self.lbl_status.setText(f"[Error] {msg[:120]}")
            self.lbl_status.setStyleSheet("color: #dc2626; font-weight: bold; font-size: 12px; background: transparent;")
            self.status_signal.emit("Embed operation reported an error")
            QMessageBox.warning(self, error_title, msg)

    def _send_last_output_to_analyzer(self):
        if self.last_output_path and os.path.isfile(self.last_output_path):
            self.analyze_created_file_signal.emit(self.last_output_path)

    def execute_lsb_embed(self):
        if not self.cover_file_path:
            QMessageBox.warning(self, "Missing Cover", "Select a cover image first.")
            return

        channels, bits = self._get_selected_channels_and_bits()
        if not channels or not bits:
            QMessageBox.warning(self, "Selection Required", "Select at least one color channel and one bit plane.")
            return

        mode_idx = self.combo_lsb_mode.currentIndex()
        if mode_idx == 3 and not self.radio_text.isChecked():
            QMessageBox.warning(
                self,
                "Text Required",
                "Visual Bit-Plane Text Stamp draws readable text onto a bit layer. Switch to 'Secret Text / Flag' above.",
            )
            return

        try:
            payload_bytes, fname = self._get_payload_bytes_and_name()
        except Exception as exc:
            QMessageBox.warning(self, "Payload Error", str(exc))
            return

        if not payload_bytes:
            QMessageBox.warning(self, "Empty Payload", "Enter secret text or select a secret file.")
            return

        password = self.input_lsb_pass.text().strip()
        if mode_idx == 2 and not password:
            QMessageBox.warning(self, "Passphrase Required", "Enter an AES-256 passphrase for encrypted LSB mode.")
            return

        default_out = os.path.splitext(self.cover_file_path)[0] + "_stego.png"
        out_path, sel_filter = QFileDialog.getSaveFileName(
            self,
            "Save LSB Stego Image (Lossless PNG or BMP)",
            default_out,
            "PNG Image (*.png);;BMP Image (*.bmp)",
        )
        if not out_path:
            return
        out_path = _ensure_extension(out_path, sel_filter, ".png")
        cover_path = self.cover_file_path

        def _job() -> Tuple[bool, str, str]:
            if mode_idx == 3:
                ch = channels[0]
                bt = bits[0]
                text_str = payload_bytes.decode("utf-8", errors="replace")
                stamp_visual_text_on_bitplane(cover_path, out_path, text_str, channel=ch, bit=bt)
                return True, out_path, f"Stamped visual text onto {ch} channel Bit {bt}"

            mode_key = {0: "raw_zsteg", 1: "framed", 2: "aes_gcm"}[mode_idx]
            written, _ = embed_lsb_data(
                cover_image_path=cover_path,
                output_path=out_path,
                payload_bytes=payload_bytes,
                channels=channels,
                bits=bits,
                mode=mode_key,
                password=password,
                filename=fname,
            )
            summary = f"Embedded {written:,} bytes into LSB ({','.join(channels)} bits {','.join(map(str, bits))}, mode={mode_key})"
            return True, out_path, summary

        self._run_async_embed(_job, "LSB Embedding Error")

    def execute_cli_embed(self):
        if not self.cover_file_path:
            QMessageBox.warning(self, "Missing Cover", "Select a cover file first.")
            return
        try:
            payload_bytes, fname = self._get_payload_bytes_and_name()
        except Exception as exc:
            QMessageBox.warning(self, "Payload Error", str(exc))
            return

        if not payload_bytes:
            QMessageBox.warning(self, "Empty Payload", "Enter secret text or select a secret file.")
            return

        tool_idx = self.combo_cli_tool.currentIndex()
        password = self.input_cli_pass.text().strip()
        comp_level = self.spin_steghide_comp.value()
        ext = os.path.splitext(self.cover_file_path)[1] or (".png" if tool_idx == 2 else ".jpg")
        default_out = os.path.splitext(self.cover_file_path)[0] + f"_stego{ext}"
        out_path, sel_filter = QFileDialog.getSaveFileName(
            self,
            "Save Stego File",
            default_out,
            f"*{ext};;All Files (*)",
        )
        if not out_path:
            return
        out_path = _ensure_extension(out_path, sel_filter, ext)
        cover_path = self.cover_file_path

        def _job() -> Tuple[bool, str, str]:
            if tool_idx == 0:
                ok, msg = embed_with_steghide(
                    cover_path,
                    out_path,
                    payload_bytes,
                    payload_filename=fname,
                    passphrase=password,
                    compression_level=comp_level,
                )
            elif tool_idx == 1:
                ok, msg = embed_with_outguess(
                    cover_path,
                    out_path,
                    payload_bytes,
                    passphrase=password,
                )
            else:
                ok, msg = embed_with_openstego(
                    cover_path,
                    out_path,
                    payload_bytes,
                    payload_filename=fname,
                    passphrase=password,
                )
            return ok, out_path, msg

        self._run_async_embed(_job, "CLI Tool Notice")

    def execute_meta_embed(self):
        if not self.cover_file_path:
            QMessageBox.warning(self, "Missing Cover", "Select a cover file first.")
            return
        try:
            payload_bytes, _fname = self._get_payload_bytes_and_name()
        except Exception as exc:
            if self.combo_meta_technique.currentIndex() != 2:
                QMessageBox.warning(self, "Payload Error", str(exc))
                return
            payload_bytes = b""

        tech_idx = self.combo_meta_technique.currentIndex()
        if tech_idx in (0, 1) and not payload_bytes:
            QMessageBox.warning(self, "Empty Payload", "Enter secret text or select a secret file to inject.")
            return

        ctype = self.combo_png_chunk.currentText().strip()
        keyword = self.input_png_keyword.text().strip()
        artist = self.input_exif_artist.text().strip()
        copyright_val = self.input_exif_copyright.text().strip()

        ext = os.path.splitext(self.cover_file_path)[1] or ".png"
        default_out = os.path.splitext(self.cover_file_path)[0] + f"_meta{ext}"
        out_path, sel_filter = QFileDialog.getSaveFileName(
            self,
            "Save Injected File",
            default_out,
            f"*{ext};;All Files (*)",
        )
        if not out_path:
            return
        out_path = _ensure_extension(out_path, sel_filter, ext)
        cover_path = self.cover_file_path

        def _job() -> Tuple[bool, str, str]:
            if tech_idx == 0:
                orig_sz, new_sz = append_eof_payload(cover_path, out_path, payload_bytes)
                return (
                    True,
                    out_path,
                    f"Appended {len(payload_bytes):,} bytes after EOF (Cover: {orig_sz:,} B -> Total: {new_sz:,} B)",
                )
            elif tech_idx == 1:
                msg = inject_png_chunk(
                    cover_path,
                    out_path,
                    chunk_type=ctype,
                    keyword=keyword,
                    secret_payload=payload_bytes,
                )
                return True, out_path, msg
            else:
                comment_str = payload_bytes.decode("utf-8", errors="replace") if payload_bytes else ""
                fields = {
                    "UserComment": comment_str,
                    "ImageDescription": comment_str,
                    "Comment": comment_str,
                    "Artist": artist,
                    "Copyright": copyright_val,
                }
                msg = inject_exif_metadata(cover_path, out_path, fields)
                return True, out_path, msg

        self._run_async_embed(_job, "Injection Error")
