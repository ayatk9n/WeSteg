# WeSteg - Reusable UI Widgets

import os
import re
from typing import Optional
from PIL import Image
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QImage, QPixmap, QFont
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
    QFileDialog,
)

MAX_RENDER_DIM = 8192
MAX_CONSOLE_CHARS = 100_000


def pil_to_qpixmap(pil_img: Image.Image) -> QPixmap:
    rgba_img = pil_img.convert("RGBA") if pil_img.mode != "RGBA" else pil_img
    data = rgba_img.tobytes("raw", "RGBA")
    qimg = QImage(
        data,
        rgba_img.width,
        rgba_img.height,
        rgba_img.width * 4,
        QImage.Format.Format_RGBA8888,
    ).copy()
    return QPixmap.fromImage(qimg)


def pil_to_thumbnail_qpixmap(pil_img: Image.Image, max_w: int, max_h: int, smooth: bool = False) -> QPixmap:
    thumb = pil_img.copy()
    resample = Image.Resampling.LANCZOS if smooth else Image.Resampling.NEAREST
    thumb.thumbnail((max_w, max_h), resample)
    return pil_to_qpixmap(thumb)


class ThumbnailCard(QFrame):

    clicked = pyqtSignal(str, object)

    def __init__(self, label: str, pil_image: Image.Image, subtitle: str = "", parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.label_text = label
        self.pil_image = pil_image
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setObjectName("ThumbnailCard")
        self.setStyleSheet(
            """
            QFrame#ThumbnailCard {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #ffffff, stop:0.65 #f7fafd, stop:1 #eaeff5);
                border: 2px solid #c3cfd9;
                border-radius: 14px;
            }
            QFrame#ThumbnailCard:hover {
                border: 2px solid #2ab7eb;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #ffffff, stop:1 #e5f6fe);
            }
            """
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(5)

        self.img_label = QLabel()
        self.img_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.img_label.setFixedSize(170, 130)
        self.img_label.setStyleSheet(
            "background-color: #dde5ed; border: 1px solid #bdcad7; border-radius: 8px;"
        )

        pix = pil_to_thumbnail_qpixmap(pil_image, 164, 124, smooth=False)
        self.img_label.setPixmap(pix)
        layout.addWidget(self.img_label, alignment=Qt.AlignmentFlag.AlignCenter)

        title_lbl = QLabel(label)
        title_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_lbl.setStyleSheet("color: #24303c; font-weight: bold; font-size: 11px; background: transparent;")
        layout.addWidget(title_lbl)

        if subtitle:
            sub_lbl = QLabel(subtitle)
            sub_lbl.setWordWrap(True)
            sub_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            sub_lbl.setStyleSheet("color: #5f6f80; font-size: 10px; background: transparent;")
            layout.addWidget(sub_lbl)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self.label_text, self.pil_image)
        super().mousePressEvent(event)


class ZoomableImageViewer(QWidget):

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.current_pil: Optional[Image.Image] = None
        self._base_pixmap: Optional[QPixmap] = None
        self.current_title: str = "No Layer Selected"
        self.zoom_factor: float = 1.0

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        toolbar = QHBoxLayout()
        self.title_label = QLabel("Click any bit-plane or filter tile to inspect")
        self.title_label.setStyleSheet("color: #086494; font-weight: bold; font-size: 13px;")
        toolbar.addWidget(self.title_label)
        toolbar.addStretch()

        self.btn_zoom_out = QPushButton("- Zoom Out")
        self.btn_zoom_reset = QPushButton("100%")
        self.btn_zoom_in = QPushButton("+ Zoom In")
        self.btn_save = QPushButton("Export Layer PNG")
        self.btn_save.setObjectName("PrimaryPill")

        for b in (self.btn_zoom_out, self.btn_zoom_reset, self.btn_zoom_in, self.btn_save):
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            toolbar.addWidget(b)

        self.btn_zoom_out.clicked.connect(lambda: self.adjust_zoom(0.8))
        self.btn_zoom_reset.clicked.connect(lambda: self.set_zoom(1.0))
        self.btn_zoom_in.clicked.connect(lambda: self.adjust_zoom(1.25))
        self.btn_save.clicked.connect(self.export_current_image)

        layout.addLayout(toolbar)

        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setStyleSheet(
            "background-color: #dce4ec; border: 2px solid #c2cedb; border-radius: 16px;"
        )

        self.canvas_label = QLabel()
        self.canvas_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.canvas_label.setStyleSheet("background: transparent;")
        self.scroll_area.setWidget(self.canvas_label)
        layout.addWidget(self.scroll_area, stretch=1)

    def set_image(self, title: str, pil_image: Image.Image):
        self.current_title = title
        self.current_pil = pil_image
        self._base_pixmap = pil_to_qpixmap(pil_image)
        self.title_label.setText(f"{title}  ({pil_image.width} x {pil_image.height} px)")
        self._render_pixmap()

    def adjust_zoom(self, multiplier: float):
        self.set_zoom(max(0.1, min(12.0, self.zoom_factor * multiplier)))

    def set_zoom(self, factor: float):
        if self._base_pixmap:
            max_safe_factor = min(
                12.0,
                MAX_RENDER_DIM / max(1, self._base_pixmap.width()),
                MAX_RENDER_DIM / max(1, self._base_pixmap.height()),
            )
            factor = min(factor, max(1.0, max_safe_factor))
        self.zoom_factor = factor
        self.btn_zoom_reset.setText(f"{int(self.zoom_factor * 100)}%")
        self._render_pixmap()

    def _render_pixmap(self):
        if not self._base_pixmap:
            return
        if abs(self.zoom_factor - 1.0) < 1e-3:
            self.canvas_label.setPixmap(self._base_pixmap)
            return
        target_w = min(MAX_RENDER_DIM, max(1, int(self._base_pixmap.width() * self.zoom_factor)))
        target_h = min(MAX_RENDER_DIM, max(1, int(self._base_pixmap.height() * self.zoom_factor)))
        scaled = self._base_pixmap.scaled(
            target_w,
            target_h,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.FastTransformation,
        )
        self.canvas_label.setPixmap(scaled)

    def export_current_image(self):
        if not self.current_pil:
            return
        clean_stem = re.sub(r"[^a-z0-9_]+", "_", self.current_title.lower()).strip("_") or "layer"
        safe_name = f"{clean_stem}.png"
        out_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Bit-Plane / Filtered Image",
            safe_name,
            "PNG Image (*.png)",
        )
        if out_path:
            if not os.path.splitext(out_path)[1]:
                out_path += ".png"
            self.current_pil.save(out_path)


class AnalyzerCardWidget(QFrame):

    def __init__(
        self,
        title: str,
        badge_text: str,
        status: str,
        output_text: str,
        command_run: str = "",
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)
        self.setObjectName("AnalyzerCard")
        border_colors = {
            "hit": "#16a34a",
            "clean": "#c4d0dc",
            "info": "#2ab7eb",
            "missing": "#e09b24",
            "error": "#ef4444",
        }
        badge_bg = {
            "hit": "#15803d",
            "clean": "#64748b",
            "info": "#0284c7",
            "missing": "#b45309",
            "error": "#dc2626",
        }
        b_col = border_colors.get(status, "#c4d0dc")
        bg_col = badge_bg.get(status, "#64748b")

        self.setStyleSheet(
            f"""
            QFrame#AnalyzerCard {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #ffffff, stop:1 #f2f7fb);
                border: 2px solid {b_col};
                border-radius: 14px;
            }}
            """
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(6)

        header = QHBoxLayout()
        title_lbl = QLabel(title)
        title_lbl.setStyleSheet("color: #1e293b; font-weight: bold; font-size: 13px; background: transparent;")
        header.addWidget(title_lbl)

        if command_run:
            cmd_lbl = QLabel(f"  $ {command_run}")
            cmd_lbl.setStyleSheet("color: #5b6b7c; font-family: monospace; font-size: 11px; background: transparent;")
            header.addWidget(cmd_lbl)

        header.addStretch()

        badge = QLabel(f" {badge_text} ")
        badge.setStyleSheet(
            f"background-color: {bg_col}; color: #ffffff; font-weight: bold; "
            "font-size: 11px; padding: 3px 10px; border-radius: 11px;"
        )
        header.addWidget(badge)

        self.toggle_btn = QPushButton("Hide" if status in ("hit", "info") else "Show")
        self.toggle_btn.setFixedWidth(72)
        self.toggle_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.toggle_btn.clicked.connect(self._toggle_body)
        header.addWidget(self.toggle_btn)

        layout.addLayout(header)

        display_text = (
            output_text[:MAX_CONSOLE_CHARS]
            + f"\n\n[... Output truncated at {MAX_CONSOLE_CHARS:,} characters for UI responsiveness ...]"
            if len(output_text) > MAX_CONSOLE_CHARS
            else output_text
        )

        self.console = QPlainTextEdit()
        self.console.setReadOnly(True)
        self.console.setPlainText(display_text)
        font = QFont("Consolas")
        font.setStyleHint(QFont.StyleHint.Monospace)
        font.setPointSize(9)
        self.console.setFont(font)
        line_count = min(14, max(4, display_text.count("\n") + 2))
        self.console.setFixedHeight(line_count * 18)
        self.console.setStyleSheet(
            "background-color: #f3f7fb; color: #1e293b; border: 1px solid #cbd6e2; border-radius: 10px; padding: 6px;"
        )
        self.console.setVisible(status in ("hit", "info"))
        layout.addWidget(self.console)

    def _toggle_body(self):
        vis = not self.console.isVisible()
        self.console.setVisible(vis)
        self.toggle_btn.setText("Hide" if vis else "Show")
