# WeSteg - Visual Bit-Plane Inspector View

import os
import re
from typing import Dict, List, Optional
from PyQt6.QtCore import QObject, QRunnable, Qt, QThreadPool, pyqtSignal
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from app.core.bitplanes import (
    BitPlaneItem,
    FilterPlaneItem,
    analyze_visual_layers,
    compute_image_xor_diff,
)
from app.ui.widgets import ThumbnailCard, ZoomableImageViewer


class VisualWorkerSignals(QObject):
    layers_ready = pyqtSignal(int, str, object, object, str)


class VisualLayerTask(QRunnable):
    def __init__(self, run_id: int, image_path: str, signals: VisualWorkerSignals):
        super().__init__()
        self.run_id = run_id
        self.image_path = image_path
        self.signals = signals

    def run(self):
        try:
            planes, transforms = analyze_visual_layers(self.image_path)
            err = ""
        except Exception as exc:
            planes, transforms = {}, []
            err = str(exc)
        try:
            self.signals.layers_ready.emit(self.run_id, self.image_path, planes, transforms, err)
        except RuntimeError:
            pass


class VisualTab(QWidget):

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.current_image_path: str = ""
        self.bit_planes: Dict[str, List[BitPlaneItem]] = {}
        self.color_transforms: List[FilterPlaneItem] = []
        self._active_run_id: int = 0
        self.thread_pool = QThreadPool.globalInstance()

        self.signals = VisualWorkerSignals(self)
        self.signals.layers_ready.connect(self._on_layers_ready)

        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        top_bar = QFrame()
        top_bar.setObjectName("ControlDeckBar")
        tb_layout = QHBoxLayout(top_bar)
        tb_layout.setContentsMargins(10, 6, 10, 6)

        self.btn_open = QPushButton("Load Image...")
        self.btn_open.setObjectName("PrimaryPill")
        self.btn_open.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_open.clicked.connect(self.browse_image)
        tb_layout.addWidget(self.btn_open)

        view_lbl = QLabel("View Mode:")
        view_lbl.setStyleSheet("color: #3a4856; font-weight: bold; background: transparent;")
        tb_layout.addWidget(view_lbl)
        self.combo_filter = QComboBox()
        self.combo_filter.addItems(
            [
                "All Bit-Planes & Filters (48 Layers)",
                "Red Channel (Bits 0-7)",
                "Green Channel (Bits 0-7)",
                "Blue Channel (Bits 0-7)",
                "Alpha Channel (Bits 0-7)",
                "RGB Combined (Bits 0-7)",
                "Color Remapping & Forensic Filters (8 Transforms)",
                "Least Significant Bits Only (Bit 0 & Bit 1 across all channels)",
            ]
        )
        self.combo_filter.currentIndexChanged.connect(self.populate_grid)
        tb_layout.addWidget(self.combo_filter)

        self.lbl_status = QLabel("No image loaded")
        self.lbl_status.setStyleSheet("color: #5a6a7a; font-size: 11px; background: transparent;")
        tb_layout.addWidget(self.lbl_status)

        tb_layout.addStretch()

        self.btn_xor = QPushButton("Compare / XOR Against Original...")
        self.btn_xor.setToolTip("Select a second image (e.g. original cover) to highlight modified stego pixels")
        self.btn_xor.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_xor.clicked.connect(self.run_xor_comparison)
        tb_layout.addWidget(self.btn_xor)

        self.btn_export_all = QPushButton("Export All Bit-Planes...")
        self.btn_export_all.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_export_all.clicked.connect(self.export_all_planes)
        tb_layout.addWidget(self.btn_export_all)

        root.addWidget(top_bar)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        self.grid_scroll = QScrollArea()
        self.grid_scroll.setWidgetResizable(True)
        self.grid_scroll.setStyleSheet(
            "border: 2px solid #c3cfd9; border-radius: 16px; background-color: rgba(255, 255, 255, 165);"
        )

        self.grid_container = QWidget()
        self.grid_container.setStyleSheet("background: transparent;")
        self.grid_layout = QGridLayout(self.grid_container)
        self.grid_layout.setContentsMargins(10, 10, 10, 10)
        self.grid_layout.setSpacing(10)
        self.grid_scroll.setWidget(self.grid_container)

        splitter.addWidget(self.grid_scroll)

        self.viewer = ZoomableImageViewer()
        splitter.addWidget(self.viewer)

        splitter.setSizes([640, 560])
        root.addWidget(splitter, stretch=1)

    def browse_image(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Image for Visual Bit-Plane Inspection",
            "",
            "Images (*.png *.jpg *.jpeg *.bmp *.gif *.webp *.tiff)",
        )
        if path:
            self.load_image(path, explicit=True)

    def load_image(self, image_path: str, explicit: bool = False):
        if not os.path.isfile(image_path):
            return
        self._active_run_id += 1
        run_id = self._active_run_id
        self._explicit_request = explicit
        self.lbl_status.setText(f"Decomposing {os.path.basename(image_path)}...")
        self.lbl_status.setStyleSheet("color: #086494; font-weight: bold; font-size: 11px; background: transparent;")

        task = VisualLayerTask(run_id, image_path, self.signals)
        self.thread_pool.start(task)

    def _on_layers_ready(
        self,
        run_id: int,
        image_path: str,
        planes: Dict[str, List[BitPlaneItem]],
        transforms: List[FilterPlaneItem],
        error: str,
    ):
        if run_id != self._active_run_id:
            return
        if error or not planes:
            self.lbl_status.setText("Non-image binary or unsupported format")
            self.lbl_status.setStyleSheet("color: #5a6a7a; font-size: 11px; background: transparent;")
            if getattr(self, "_explicit_request", False) and error:
                QMessageBox.warning(self, "Visual Inspector", error)
            return

        self.current_image_path = image_path
        self.bit_planes = planes
        self.color_transforms = transforms
        self.lbl_status.setText(f"48 layers ready ({os.path.basename(image_path)})")
        self.lbl_status.setStyleSheet("color: #15803d; font-weight: bold; font-size: 11px; background: transparent;")
        self.populate_grid()
        if self.bit_planes.get("Red"):
            first = self.bit_planes["Red"][0]
            self.viewer.set_image(first.label, first.image)

    def _clear_grid(self):
        while self.grid_layout.count():
            item = self.grid_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

    def populate_grid(self):
        self._clear_grid()
        if not self.bit_planes:
            return

        mode_idx = self.combo_filter.currentIndex()
        cards_to_add = []

        if mode_idx == 0:
            for ch in ("Red", "Green", "Blue", "Alpha", "RGB"):
                for item in self.bit_planes.get(ch, []):
                    cards_to_add.append((item.label, item.image, f"{ch} Channel"))
            for tf in self.color_transforms:
                cards_to_add.append((tf.name, tf.image, tf.description))
        elif mode_idx in (1, 2, 3, 4, 5):
            ch_names = {1: "Red", 2: "Green", 3: "Blue", 4: "Alpha", 5: "RGB"}
            ch = ch_names[mode_idx]
            for item in self.bit_planes.get(ch, []):
                cards_to_add.append((item.label, item.image, f"Bit {item.bit} layer"))
        elif mode_idx == 6:
            for tf in self.color_transforms:
                cards_to_add.append((tf.name, tf.image, tf.description))
        elif mode_idx == 7:
            for ch in ("Red", "Green", "Blue", "Alpha", "RGB"):
                for item in self.bit_planes.get(ch, [])[:2]:
                    cards_to_add.append((item.label, item.image, "Lower LSB Layer"))

        cols = 3
        for idx, (label, pil_img, sub) in enumerate(cards_to_add):
            r = idx // cols
            c = idx % cols
            card = ThumbnailCard(label=label, pil_image=pil_img, subtitle=sub)
            card.clicked.connect(self.viewer.set_image)
            self.grid_layout.addWidget(card, r, c)

    def run_xor_comparison(self):
        if not self.current_image_path:
            QMessageBox.information(self, "Load Image First", "Please load a primary image first.")
            return
        other_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Second Image (Original Carrier) for Pixel XOR Comparison",
            "",
            "Images (*.png *.jpg *.jpeg *.bmp *.gif *.webp *.tiff)",
        )
        if not other_path:
            return
        try:
            diff_img = compute_image_xor_diff(self.current_image_path, other_path)
            self.viewer.set_image(f"XOR Diff vs {os.path.basename(other_path)} (Amplified)", diff_img)
        except Exception as exc:
            QMessageBox.critical(self, "XOR Error", str(exc))

    def export_all_planes(self):
        if not self.bit_planes:
            QMessageBox.information(self, "No Image", "Load an image before exporting bit planes.")
            return
        out_dir = QFileDialog.getExistingDirectory(self, "Select Folder to Export All Bit-Planes")
        if not out_dir:
            return
        count = 0
        for ch, items in self.bit_planes.items():
            for item in items:
                fname = f"plane_{ch.lower()}_bit{item.bit}.png"
                item.image.save(os.path.join(out_dir, fname))
                count += 1
        for idx, tf in enumerate(self.color_transforms, start=1):
            clean_tf = re.sub(r"[^a-z0-9_]+", "_", tf.name.lower()).strip("_")
            fname = f"filter_{idx}_{clean_tf}.png"
            tf.image.save(os.path.join(out_dir, fname))
            count += 1
        QMessageBox.information(self, "Export Complete", f"Exported {count} bit-plane and filter PNGs to:\n{out_dir}")
