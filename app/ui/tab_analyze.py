# WeSteg - Analyze & Extract View

import atexit
import os
import shutil
import tempfile
from typing import List, Optional
from PIL import Image
from PyQt6.QtCore import QObject, QRunnable, Qt, QThreadPool, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.core.analyzers import (
    AnalyzerResult,
    ExtractedArtifact,
    run_binwalk_foremost_analyzer,
    run_exiftool_analyzer,
    run_file_and_hashes,
    run_outguess_analyzer,
    run_pngcheck_analyzer,
    run_steghide_analyzer,
    run_strings_analyzer,
    run_zsteg_analyzer,
)
from app.ui.widgets import AnalyzerCardWidget, pil_to_thumbnail_qpixmap


class AnalyzerSignals(QObject):
    result_ready = pyqtSignal(int, object)


class SingleAnalyzerTask(QRunnable):
    def __init__(self, run_id: int, fn, signals: AnalyzerSignals, *args, **kwargs):
        super().__init__()
        self.run_id = run_id
        self.fn = fn
        self.signals = signals
        self.args = args
        self.kwargs = kwargs

    def run(self):
        try:
            res = self.fn(*self.args, **self.kwargs)
        except Exception as exc:
            res = AnalyzerResult(
                tool_id="error",
                title="Analyzer Exception",
                status="error",
                badge_text="Error",
                output_text=str(exc),
            )
        try:
            self.signals.result_ready.emit(self.run_id, res)
        except RuntimeError:
            pass


class AnalyzeTab(QWidget):

    image_loaded_signal = pyqtSignal(str)
    status_signal = pyqtSignal(str)

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.current_file: str = ""
        self.workspace_dir: str = ""
        self._all_workspaces: List[str] = []
        self.thread_pool = QThreadPool.globalInstance()
        self._active_run_id: int = 0
        self.pending_tasks: int = 0
        self.total_tasks: int = 0
        self.collected_artifacts: List[ExtractedArtifact] = []

        self.signals = AnalyzerSignals(self)
        self.signals.result_ready.connect(self._on_analyzer_result)

        atexit.register(self.cleanup_workspaces)
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        top_bar = QFrame()
        top_bar.setObjectName("ControlDeckBar")
        tb_layout = QHBoxLayout(top_bar)
        tb_layout.setContentsMargins(10, 6, 10, 6)

        self.btn_browse = QPushButton("Load Image / File...")
        self.btn_browse.setObjectName("PrimaryPill")
        self.btn_browse.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_browse.clicked.connect(self.browse_file)
        tb_layout.addWidget(self.btn_browse)

        self.lbl_path = QLabel("Drag & drop an image anywhere or click 'Load Image / File...'")
        self.lbl_path.setStyleSheet("color: #5a6a7a; font-size: 12px; background: transparent;")
        tb_layout.addWidget(self.lbl_path, stretch=1)

        pass_lbl = QLabel("Passphrase:")
        pass_lbl.setStyleSheet("color: #3a4856; font-weight: bold; background: transparent;")
        tb_layout.addWidget(pass_lbl)
        self.input_password = QLineEdit()
        self.input_password.setPlaceholderText("Optional password (steghide, outguess, AES-LSB)...")
        self.input_password.setFixedWidth(250)
        tb_layout.addWidget(self.input_password)

        self.chk_zsteg_all = QCheckBox("zsteg --all")
        self.chk_zsteg_all.setStyleSheet("background: transparent; font-weight: bold;")
        self.chk_zsteg_all.setToolTip("Run exhaustive zsteg bit/channel permutation scan")
        tb_layout.addWidget(self.chk_zsteg_all)

        self.btn_run = QPushButton("Run Full Analysis")
        self.btn_run.setObjectName("PrimaryPill")
        self.btn_run.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_run.clicked.connect(self.start_analysis)
        tb_layout.addWidget(self.btn_run)

        root.addWidget(top_bar)

        self.progress = QProgressBar()
        self.progress.setFixedHeight(8)
        self.progress.setTextVisible(False)
        self.progress.setVisible(False)
        root.addWidget(self.progress)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        left_panel = QWidget()
        left_panel.setStyleSheet("background: transparent;")
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(8)

        preview_frame = QFrame()
        preview_frame.setObjectName("PreviewMonitor")
        pf_layout = QVBoxLayout(preview_frame)
        self.lbl_preview = QLabel("No Image Loaded")
        self.lbl_preview.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_preview.setMinimumSize(280, 220)
        self.lbl_preview.setStyleSheet("color: #64748b; font-weight: bold; background: transparent;")
        pf_layout.addWidget(self.lbl_preview)
        left_layout.addWidget(preview_frame)

        art_header = QHBoxLayout()
        art_lbl = QLabel("Carved & Extracted Payloads")
        art_lbl.setStyleSheet("color: #24303c; font-weight: bold; font-size: 13px; background: transparent;")
        art_header.addWidget(art_lbl)
        art_header.addStretch()

        self.btn_save_artifact = QPushButton("Save Selected")
        self.btn_save_artifact.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_save_artifact.clicked.connect(self.save_selected_artifact)
        art_header.addWidget(self.btn_save_artifact)
        left_layout.addLayout(art_header)

        self.tree_artifacts = QTreeWidget()
        self.tree_artifacts.setHeaderLabels(["Artifact Name", "Size", "Source Tool", "Details"])
        self.tree_artifacts.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.tree_artifacts.setMinimumHeight(180)
        left_layout.addWidget(self.tree_artifacts, stretch=1)

        splitter.addWidget(left_panel)

        self.cards_scroll = QScrollArea()
        self.cards_scroll.setWidgetResizable(True)
        self.cards_scroll.setStyleSheet("background: transparent; border: none;")

        self.cards_container = QWidget()
        self.cards_container.setStyleSheet("background: transparent;")
        self.cards_layout = QVBoxLayout(self.cards_container)
        self.cards_layout.setContentsMargins(4, 0, 4, 0)
        self.cards_layout.setSpacing(10)
        self.cards_layout.addStretch()

        self.cards_scroll.setWidget(self.cards_container)
        splitter.addWidget(self.cards_scroll)

        splitter.setSizes([340, 820])
        root.addWidget(splitter, stretch=1)

    def browse_file(self) -> bool:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Image or File to Analyze",
            "",
            "Images & Media (*.png *.jpg *.jpeg *.bmp *.gif *.webp *.tiff *.wav *.au);;All Files (*)",
        )
        if path:
            self.load_file(path)
            return True
        return False

    def load_file(self, file_path: str):
        if not os.path.isfile(file_path):
            return
        self.current_file = file_path
        self.lbl_path.setText(file_path)
        self.lbl_path.setStyleSheet("color: #086494; font-weight: bold; font-size: 12px; background: transparent;")

        try:
            with Image.open(file_path) as pil_img:
                pix = pil_to_thumbnail_qpixmap(pil_img, 290, 220, smooth=True)
            self.lbl_preview.setPixmap(pix)
        except Exception:
            self.lbl_preview.clear()
            self.lbl_preview.setText(f"Binary File:\n{os.path.basename(file_path)}")

        self.image_loaded_signal.emit(file_path)
        self.start_analysis()

    def _clear_cards(self):
        while self.cards_layout.count() > 1:
            item = self.cards_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()
        self.tree_artifacts.clear()
        self.collected_artifacts.clear()

    def _prune_inactive_workspaces(self):
        if self.thread_pool.activeThreadCount() == 0 and len(self._all_workspaces) > 1:
            stale = self._all_workspaces[:-1]
            self._all_workspaces = self._all_workspaces[-1:]
            for d in stale:
                shutil.rmtree(d, ignore_errors=True)

    def cleanup_workspaces(self):
        while self._all_workspaces:
            d = self._all_workspaces.pop()
            shutil.rmtree(d, ignore_errors=True)

    def start_analysis(self):
        if not self.current_file or not os.path.isfile(self.current_file):
            QMessageBox.information(self, "No File Selected", "Please load an image or file to analyze first.")
            return

        self._prune_inactive_workspaces()
        self._clear_cards()

        self._active_run_id += 1
        run_id = self._active_run_id

        password = self.input_password.text().strip()
        zsteg_all = self.chk_zsteg_all.isChecked()

        self.workspace_dir = tempfile.mkdtemp(prefix="westeg_session_")
        self._all_workspaces.append(self.workspace_dir)

        tasks = [
            (run_file_and_hashes, (self.current_file,), {}),
            (run_exiftool_analyzer, (self.current_file,), {}),
            (run_pngcheck_analyzer, (self.current_file, self.workspace_dir), {}),
            (
                run_zsteg_analyzer,
                (self.current_file, self.workspace_dir),
                {"run_all": zsteg_all, "password": password},
            ),
            (run_steghide_analyzer, (self.current_file, self.workspace_dir), {"password": password}),
            (run_outguess_analyzer, (self.current_file, self.workspace_dir), {"password": password}),
            (run_binwalk_foremost_analyzer, (self.current_file, self.workspace_dir), {}),
            (run_strings_analyzer, (self.current_file,), {}),
        ]

        self.total_tasks = len(tasks)
        self.pending_tasks = len(tasks)
        self.progress.setRange(0, self.total_tasks)
        self.progress.setValue(0)
        self.progress.setVisible(True)
        self.btn_run.setEnabled(False)
        self.status_signal.emit(f"Scanning {os.path.basename(self.current_file)}...")

        for fn, args, kwargs in tasks:
            runnable = SingleAnalyzerTask(run_id, fn, self.signals, *args, **kwargs)
            self.thread_pool.start(runnable)

    def _on_analyzer_result(self, run_id: int, result: AnalyzerResult):
        if run_id != self._active_run_id:
            return

        card = AnalyzerCardWidget(
            title=result.title,
            badge_text=result.badge_text,
            status=result.status,
            output_text=result.output_text,
            command_run=result.command_run,
        )
        insert_idx = 0 if result.status == "hit" else max(0, self.cards_layout.count() - 1)
        self.cards_layout.insertWidget(insert_idx, card)

        for art in result.artifacts:
            self.collected_artifacts.append(art)
            item = QTreeWidgetItem(
                [
                    art.name,
                    f"{art.size:,} B",
                    art.source_tool,
                    art.description,
                ]
            )
            item.setData(0, Qt.ItemDataRole.UserRole, art.path)
            self.tree_artifacts.addTopLevelItem(item)

        self.pending_tasks = max(0, self.pending_tasks - 1)
        self.progress.setValue(self.total_tasks - self.pending_tasks)

        if self.pending_tasks == 0:
            self.progress.setVisible(False)
            self.btn_run.setEnabled(True)
            self._prune_inactive_workspaces()
            self.status_signal.emit(
                f"Scan complete: {os.path.basename(self.current_file)} ({len(self.collected_artifacts)} payloads)"
            )

    def save_selected_artifact(self):
        item = self.tree_artifacts.currentItem()
        if not item:
            QMessageBox.information(self, "Select Payload", "Click an extracted payload in the list first.")
            return
        src_path = item.data(0, Qt.ItemDataRole.UserRole)
        if not src_path or os.path.islink(src_path) or not os.path.isfile(src_path):
            QMessageBox.warning(self, "Unavailable", "Selected artifact file is missing or unsafe.")
            return

        default_name = os.path.basename(item.text(0)) or "extracted_payload.bin"
        dest_path, _ = QFileDialog.getSaveFileName(self, "Save Extracted Payload", default_name, "All Files (*)")
        if dest_path:
            shutil.copyfile(src_path, dest_path)
            QMessageBox.information(self, "Saved", f"Saved extracted payload to:\n{dest_path}")
