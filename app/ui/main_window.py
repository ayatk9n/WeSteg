# WeSteg - Main Window

import os
from typing import List, Optional
from PyQt6.QtCore import QObject, QRunnable, Qt, QThreadPool, pyqtSignal
from PyQt6.QtGui import QCloseEvent, QColor, QDragEnterEvent, QDropEvent, QFont
from PyQt6.QtWidgets import (
    QButtonGroup,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMainWindow,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.core.tool_checker import ToolStatus, check_all_tools
from app.ui.tab_analyze import AnalyzeTab
from app.ui.tab_hide import HideStudioTab
from app.ui.tab_visual import VisualTab
from app.ui.theme import (
    CHANNEL_THEME_STYLESHEET,
    ChannelTileCard,
    CurvedSystemFooter,
    PinstripeBackdrop,
)


CHEATSHEET_TEXT = """================================================================================
              WESTEG FORENSIC & STEGANOGRAPHY TRIAGE HANDBOOK
================================================================================

[1] INITIAL TRIAGE CHECKLIST (UNKNOWN IMAGE OR FILE)
--------------------------------------------------------------------------------
  1. File Header & Hashes (`file` / `exiftool` / Native Header Engine):
     - Verify if the file extension matches its true magic bytes.
     - Check EXIF tags (`Artist`, `UserComment`, `Copyright`, `DocumentName`, GPS).
  2. Structure & Trailing Data (`pngcheck` / Native Chunk & EOF Inspector):
     - For PNG: Check for custom chunks (`tEXt`, `zTXt`, `iTXt`, `sEcR`) or bad CRCs
       in `IHDR` (which indicate tampered image width/height hiding cropped rows!).
     - Check if bytes are appended past PNG `IEND` or JPEG `FF D9` (EOF).
  3. Visual Bit-Plane Inspection (`Visual Layers`):
     - Inspect Bit 0 (LSB) and Bit 1 across Red, Green, Blue, and Alpha channels.
     - Look for QR codes, hidden text stamps, or non-random blocks at the top of Bit 0.
     - Cycle through the 8 Randomized Color Palette Maps to spot faint watermarks.

[2] FORMAT-SPECIFIC EXTRACTION WORKFLOW
--------------------------------------------------------------------------------
  * PNG / BMP (Lossless):
    -> Primary target for LSB (`zsteg`, Native LSB Scanner, `OpenStego`).
    -> Check `zsteg -a <file.png>` for LSB data across non-standard bit orders (BGR, xy).
  * JPEG / JPG (Lossy DCT):
    -> Cannot use standard spatial LSB without corruption; uses DCT coefficient tools:
       `steghide`, `stegseek`, `outguess`, `jsteg`, `jphide`.
    -> If password-protected with Steghide:
       WeSteg automatically checks `/usr/share/wordlists/rockyou.txt` via `stegseek` when available.
  * Embedded Archives & Polyglots (`binwalk` / `foremost` / Native Carver):
    -> Whenever an embedded ZIP (`PK\\x03\\x04`), RAR, PDF, or second image is detected
       inside the carrier, extract it directly from the "Carved & Extracted Payloads" tree.

[3] CREATING YOUR OWN STEGO PAYLOADS (`Hide / Embed Studio`)
--------------------------------------------------------------------------------
  * Invisible Visual Flag:
    -> Use "Visual Bit-Plane Text Stamp" (Sub-tab 1) to draw text onto Red or Alpha Bit 0.
  * Encrypted LSB:
    -> Use "AES-256-GCM Encrypted" mode (Sub-tab 1) on a PNG cover with a strong passphrase.
  * Passphrase-Protected JPEG:
    -> Use "Steghide" or "OutGuess" (Sub-tab 2) on a JPG cover image.
  * Polyglot File (Valid Image + Valid ZIP Archive):
    -> Select a `.zip` file as your payload and use "EOF File Appender" (Sub-tab 3).

[4] WINDOWS & LINUX SETUP REFERENCE
--------------------------------------------------------------------------------
  * Windows (PowerShell):
    python -m venv .venv
    .\\.venv\\Scripts\\Activate.ps1
    pip install -r requirements.txt
    python main.py
  * Linux (Debian / Ubuntu / Kali / Fedora / Arch):
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    python3 main.py
"""


class ToolCheckSignals(QObject):
    ready = pyqtSignal(object)


class ToolCheckTask(QRunnable):
    def __init__(self, signals: ToolCheckSignals):
        super().__init__()
        self.signals = signals

    def run(self):
        tools = check_all_tools()
        try:
            self.signals.ready.emit(tools)
        except RuntimeError:
            pass


class ToolStatusAndWikiTab(QWidget):

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.signals = ToolCheckSignals(self)
        self.signals.ready.connect(self._populate_table)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(10)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        left_w = QFrame()
        left_w.setObjectName("ControlDeckBar")
        l_lay = QVBoxLayout(left_w)
        l_lay.setContentsMargins(12, 12, 12, 12)
        l_lay.setSpacing(8)

        hdr = QHBoxLayout()
        lbl = QLabel("CLI Tool Status & Native Python Fallbacks")
        lbl.setStyleSheet("color: #1e293b; font-weight: bold; font-size: 14px; background: transparent;")
        hdr.addWidget(lbl)
        hdr.addStretch()

        self.btn_refresh = QPushButton("Refresh Status")
        self.btn_refresh.setObjectName("PrimaryPill")
        self.btn_refresh.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_refresh.clicked.connect(self.refresh_table)
        hdr.addWidget(self.btn_refresh)
        l_lay.addLayout(hdr)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Tool", "Binary", "Status", "Category", "Version / Fallback Info"])
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setStyleSheet("alternate-background-color: #f4f8fc;")
        l_lay.addWidget(self.table)

        tip = QLabel(
            "Tip: Native Python engines run out-of-the-box on Windows & Linux. "
            "Install optional CLI tools on PATH (or run `./setup_kali.sh` on Debian/Ubuntu/Kali)."
        )
        tip.setWordWrap(True)
        tip.setStyleSheet("color: #086494; font-weight: bold; background: transparent;")
        l_lay.addWidget(tip)

        splitter.addWidget(left_w)

        right_w = QFrame()
        right_w.setObjectName("ControlDeckBar")
        r_lay = QVBoxLayout(right_w)
        r_lay.setContentsMargins(12, 12, 12, 12)
        r_lay.setSpacing(8)

        w_lbl = QLabel("Integrated Steganography Field Manual & Cheatsheet")
        w_lbl.setStyleSheet("color: #1e293b; font-weight: bold; font-size: 14px; background: transparent;")
        r_lay.addWidget(w_lbl)

        wiki_box = QPlainTextEdit()
        wiki_box.setReadOnly(True)
        wiki_box.setPlainText(CHEATSHEET_TEXT)
        font = QFont("Consolas")
        font.setStyleHint(QFont.StyleHint.Monospace)
        font.setPointSize(9)
        wiki_box.setFont(font)
        r_lay.addWidget(wiki_box)

        splitter.addWidget(right_w)
        splitter.setSizes([640, 540])
        layout.addWidget(splitter)

        self.refresh_table()

    def refresh_table(self):
        self.btn_refresh.setEnabled(False)
        self.btn_refresh.setText("Checking...")
        QThreadPool.globalInstance().start(ToolCheckTask(self.signals))

    def _populate_table(self, tools: List[ToolStatus]):
        self.btn_refresh.setEnabled(True)
        self.btn_refresh.setText("Refresh Status")
        self.table.setRowCount(len(tools))
        for row, t in enumerate(tools):
            self.table.setItem(row, 0, QTableWidgetItem(t.name))
            self.table.setItem(row, 1, QTableWidgetItem(t.binary))

            if t.installed:
                status_text = "[OK] Installed"
                fg_col = QColor("#15803d")
            elif t.fallback_available:
                status_text = "[Native] Python Active"
                fg_col = QColor("#0284c7")
            else:
                status_text = "[Missing] CLI Not Found"
                fg_col = QColor("#b45309")

            st_item = QTableWidgetItem(status_text)
            st_item.setForeground(fg_col)
            f_bold = st_item.font()
            f_bold.setBold(True)
            st_item.setFont(f_bold)
            self.table.setItem(row, 2, st_item)
            self.table.setItem(row, 3, QTableWidgetItem(t.category))
            self.table.setItem(row, 4, QTableWidgetItem(t.version))


class ChannelHomeGrid(QWidget):

    open_page_signal = pyqtSignal(int)
    browse_file_signal = pyqtSignal()

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setStyleSheet("background: transparent;")

        outer = QVBoxLayout(self)
        outer.setContentsMargins(28, 18, 28, 18)
        outer.setSpacing(16)

        grid = QGridLayout()
        grid.setHorizontalSpacing(22)
        grid.setVerticalSpacing(20)

        self.tile_analyze = ChannelTileCard(
            tag_text="CHANNEL 01",
            title_text="Analyze & Extract",
            subtitle_text="Run parallel steganalysis, LSB & DCT scanners, password checks, and payload carving.",
            action_text="Start",
            emblem="scan",
        )
        self.tile_analyze.clicked.connect(lambda: self.open_page_signal.emit(1))

        self.tile_visual = ChannelTileCard(
            tag_text="CHANNEL 02",
            title_text="Visual Layer Studio",
            subtitle_text="Inspect 40 RGBA bit-plane slices, 8 color palette maps, and pixel XOR diffs.",
            action_text="Start",
            emblem="layers",
        )
        self.tile_visual.clicked.connect(lambda: self.open_page_signal.emit(2))

        self.tile_hide = ChannelTileCard(
            tag_text="CHANNEL 03",
            title_text="Hide & Embed Studio",
            subtitle_text="Conceal text or files via AES-256 LSB, Steghide, custom PNG chunks, or EOF polyglots.",
            action_text="Start",
            emblem="vault",
        )
        self.tile_hide.clicked.connect(lambda: self.open_page_signal.emit(3))

        self.tile_status = ChannelTileCard(
            tag_text="CHANNEL 04",
            title_text="Tools & Field Manual",
            subtitle_text="Check live CLI tool diagnostics, native Python engines, and the steganography handbook.",
            action_text="Open",
            emblem="manual",
        )
        self.tile_status.clicked.connect(lambda: self.open_page_signal.emit(4))

        self.tile_quick_load = ChannelTileCard(
            tag_text="FILE SLOT",
            title_text="Load Target Media",
            subtitle_text="Browse local filesystem to open an image, archive, or audio carrier for inspection.",
            action_text="Browse...",
            emblem="disc",
        )
        self.tile_quick_load.clicked.connect(self.browse_file_signal.emit)

        self.tile_drop_slot = ChannelTileCard(
            tag_text="DROP SLOT",
            title_text="Drag & Drop Carrier",
            subtitle_text="Drop any image or binary file anywhere on this window to launch automated analysis.",
            action_text="Select File",
            emblem="scan",
            recessed_slot=True,
        )
        self.tile_drop_slot.clicked.connect(self.browse_file_signal.emit)

        grid.addWidget(self.tile_analyze, 0, 0)
        grid.addWidget(self.tile_visual, 0, 1)
        grid.addWidget(self.tile_hide, 0, 2)
        grid.addWidget(self.tile_status, 1, 0)
        grid.addWidget(self.tile_quick_load, 1, 1)
        grid.addWidget(self.tile_drop_slot, 1, 2)

        for col in range(3):
            grid.setColumnStretch(col, 1)
        for row in range(2):
            grid.setRowStretch(row, 1)

        outer.addLayout(grid, stretch=1)


class WeStegMainWindow(QMainWindow):

    def __init__(self, initial_file: Optional[str] = None):
        super().__init__()
        self.setWindowTitle("WeSteg - Steganalysis and Steganography Suite")
        self.resize(1360, 860)
        self.setAcceptDrops(True)
        self.setStyleSheet(CHANNEL_THEME_STYLESHEET)

        central = PinstripeBackdrop()
        self.setCentralWidget(central)
        outer_layout = QVBoxLayout(central)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        upper_wrap = QWidget()
        upper_wrap.setStyleSheet("background: transparent;")
        upper_layout = QVBoxLayout(upper_wrap)
        upper_layout.setContentsMargins(16, 12, 16, 6)
        upper_layout.setSpacing(10)

        nav_bar = QFrame()
        nav_bar.setObjectName("ControlDeckBar")
        nav_layout = QHBoxLayout(nav_bar)
        nav_layout.setContentsMargins(14, 6, 14, 6)
        nav_layout.setSpacing(8)

        logo = QLabel("WeSteg")
        logo.setStyleSheet(
            "color: #086494; font-weight: 900; font-size: 19px; letter-spacing: 1px; background: transparent;"
        )
        nav_layout.addWidget(logo)

        sub = QLabel("- Steganalysis and Steganography Suite")
        sub.setStyleSheet("color: #465564; font-weight: bold; font-size: 13px; background: transparent;")
        nav_layout.addWidget(sub)
        nav_layout.addStretch()

        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)
        self.nav_buttons: List[QPushButton] = []

        nav_labels = [
            "Menu",
            "Analyze & Extract",
            "Visual Layers (48)",
            "Hide / Embed Studio",
            "Tools & Manual",
        ]
        for idx, text in enumerate(nav_labels):
            btn = QPushButton(text)
            btn.setObjectName("NavPill")
            btn.setCheckable(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda _checked, page_idx=idx: self.switch_page(page_idx))
            self.nav_group.addButton(btn, idx)
            self.nav_buttons.append(btn)
            nav_layout.addWidget(btn)

        upper_layout.addWidget(nav_bar)

        self.stack = QStackedWidget()
        self.stack.setStyleSheet("background: transparent;")

        self.page_home = ChannelHomeGrid()
        self.tab_analyze = AnalyzeTab()
        self.tab_visual = VisualTab()
        self.tab_hide = HideStudioTab()
        self.tab_status = ToolStatusAndWikiTab()

        self.stack.addWidget(self.page_home)
        self.stack.addWidget(self.tab_analyze)
        self.stack.addWidget(self.tab_visual)
        self.stack.addWidget(self.tab_hide)
        self.stack.addWidget(self.tab_status)

        upper_layout.addWidget(self.stack, stretch=1)
        outer_layout.addWidget(upper_wrap, stretch=1)

        self.footer = CurvedSystemFooter()
        self.footer.home_clicked.connect(lambda: self.switch_page(0))
        self.footer.load_clicked.connect(self._browse_and_analyze)
        outer_layout.addWidget(self.footer)

        self.page_home.open_page_signal.connect(self.switch_page)
        self.page_home.browse_file_signal.connect(self._browse_and_analyze)
        self.tab_analyze.image_loaded_signal.connect(self._on_file_loaded_globally)
        self.tab_analyze.status_signal.connect(self.footer.set_status_text)
        self.tab_hide.analyze_created_file_signal.connect(self._on_verify_created_file)
        self.tab_hide.status_signal.connect(self.footer.set_status_text)

        if initial_file and os.path.isfile(initial_file):
            self.switch_page(1)
            self.tab_analyze.load_file(initial_file)
        else:
            self.switch_page(0)

    def switch_page(self, index: int):
        if 0 <= index < self.stack.count():
            self.stack.setCurrentIndex(index)
            if 0 <= index < len(self.nav_buttons):
                self.nav_buttons[index].setChecked(True)

    def _browse_and_analyze(self):
        if self.tab_analyze.browse_file():
            self.switch_page(1)

    def _on_file_loaded_globally(self, path: str):
        self.tab_visual.load_image(path)
        fname = os.path.basename(path)
        self.page_home.tile_analyze.set_subtitle(
            f"Active target: {fname}\nClick to view parallel steganalysis results and carved artifacts."
        )

    def _on_verify_created_file(self, path: str):
        self.switch_page(1)
        self.tab_analyze.load_file(path)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        urls = event.mimeData().urls()
        if not urls:
            return
        local_path = urls[0].toLocalFile()
        if os.path.isfile(local_path):
            self.switch_page(1)
            self.tab_analyze.load_file(local_path)

    def closeEvent(self, event: QCloseEvent):
        QThreadPool.globalInstance().waitForDone(1500)
        self.tab_analyze.cleanup_workspaces()
        super().closeEvent(event)
