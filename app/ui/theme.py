# WeSteg - UI Theme & Custom Widgets

from typing import Optional
from PyQt6.QtCore import QDateTime, QPointF, QRectF, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPalette,
    QPen,
)
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)


CHANNEL_THEME_STYLESHEET = """
QMainWindow, QDialog, QMessageBox {
    background-color: #e6ebf0;
    color: #2c3640;
    font-family: "Segoe UI", "Cantarell", "DejaVu Sans", "Liberation Sans", sans-serif;
    font-size: 12px;
}
QWidget {
    color: #2c3640;
    font-family: "Segoe UI", "Cantarell", "DejaVu Sans", "Liberation Sans", sans-serif;
    font-size: 12px;
}
QFrame#ControlDeckBar {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #ffffff, stop:0.55 #f5f8fb, stop:1 #e8eef5);
    border: 2px solid #c4d0dc;
    border-radius: 18px;
    padding: 4px 10px;
}
QFrame#PreviewMonitor {
    background-color: #edf2f7;
    border: 2px solid #c2cedb;
    border-radius: 16px;
}
QGroupBox {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #ffffff, stop:0.7 #f8fafc, stop:1 #eef3f8);
    border: 2px solid #c5d1dd;
    border-radius: 16px;
    margin-top: 12px;
    padding-top: 14px;
    font-weight: bold;
    color: #2c3640;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 14px;
    padding: 2px 12px;
    background-color: #e6f6fd;
    border: 1px solid #7fd4f5;
    border-radius: 9px;
    color: #0b5d8a;
}
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #ffffff, stop:0.48 #f6f9fc, stop:0.52 #eaeff5, stop:1 #dce5ee);
    color: #2f3b47;
    border: 2px solid #b6c4d2;
    border-radius: 15px;
    padding: 6px 16px;
    font-weight: bold;
}
QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #ffffff, stop:0.5 #f0faff, stop:1 #d8f2fd);
    border: 2px solid #2ab7eb;
    color: #085a87;
}
QPushButton:pressed {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #cdeefb, stop:1 #e8f8ff);
    border: 2px solid #0095cc;
}
QPushButton:disabled {
    background: #e4e9ef;
    color: #98a5b3;
    border: 2px solid #cfd8e2;
}
QPushButton#PrimaryPill {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #ffffff, stop:0.48 #f2fbff, stop:0.52 #e1f5fe, stop:1 #ccecfc);
    color: #075985;
    border: 2px solid #2ab7eb;
    border-radius: 16px;
    padding: 7px 18px;
    font-weight: bold;
}
QPushButton#PrimaryPill:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #ffffff, stop:0.45 #e3f7ff, stop:1 #b3e6fc);
    border: 2px solid #0099db;
    color: #044366;
}
QPushButton#PrimaryPill:disabled {
    background: #e6ecf2;
    color: #9aa7b4;
    border: 2px solid #cbd5e0;
}
QPushButton#NavPill {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #ffffff, stop:0.5 #f3f7fa, stop:1 #e1e8f0);
    color: #465462;
    border: 2px solid #bcc9d6;
    border-radius: 15px;
    padding: 6px 15px;
    font-weight: bold;
}
QPushButton#NavPill:hover {
    border: 2px solid #2ab7eb;
    color: #085a87;
}
QPushButton#NavPill:checked {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #ffffff, stop:0.45 #e4f7ff, stop:1 #bfeaff);
    border: 2px solid #1aa8e0;
    color: #064e75;
}
QPushButton#ShoulderOrb {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #ffffff, stop:0.48 #f4f8fb, stop:0.52 #e3ebf3, stop:1 #d2dde8);
    color: #2c3844;
    border: 2px solid #96acc0;
    border-radius: 21px;
    padding: 8px 20px;
    font-size: 13px;
    font-weight: bold;
}
QPushButton#ShoulderOrb:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #ffffff, stop:0.5 #ebfbff, stop:1 #cbf0fe);
    border: 3px solid #2ab7eb;
    color: #065682;
}
QTabWidget::pane {
    background: rgba(255, 255, 255, 235);
    border: 2px solid #c5d1dd;
    border-radius: 16px;
    top: -2px;
}
QTabBar::tab {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #f9fbfd, stop:1 #e3eaf2);
    color: #526170;
    border: 2px solid #c5d1dd;
    border-bottom: none;
    padding: 8px 18px;
    margin-right: 6px;
    border-top-left-radius: 14px;
    border-top-right-radius: 14px;
    font-weight: bold;
}
QTabBar::tab:selected {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #ffffff, stop:1 #e6f7ff);
    color: #075985;
    border: 2px solid #2ab7eb;
    border-bottom: none;
}
QTabBar::tab:hover:!selected {
    background: #ffffff;
    border-color: #7ccdf0;
    color: #1e293b;
}
QLineEdit, QPlainTextEdit, QComboBox, QSpinBox, QTreeWidget, QTableWidget {
    background-color: #ffffff;
    color: #24303c;
    border: 2px solid #c5d1dd;
    border-radius: 10px;
    padding: 5px 8px;
    selection-background-color: #bae6fd;
    selection-color: #082f49;
}
QLineEdit:focus, QPlainTextEdit:focus, QComboBox:focus, QSpinBox:focus {
    border: 2px solid #2ab7eb;
    background-color: #fcfeff;
}
QComboBox::drop-down {
    border: none;
    width: 24px;
}
QComboBox QAbstractItemView {
    background-color: #ffffff;
    color: #24303c;
    border: 2px solid #2ab7eb;
    border-radius: 8px;
    selection-background-color: #d8f2fd;
    selection-color: #064e75;
    outline: none;
}
QToolTip {
    background-color: #ffffff;
    color: #1e293b;
    border: 2px solid #2ab7eb;
    border-radius: 8px;
    padding: 4px 8px;
}
QHeaderView::section {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #f8fafc, stop:1 #e5ecf3);
    color: #3f4e5e;
    border: 1px solid #cbd5e1;
    padding: 6px;
    font-weight: bold;
}
QProgressBar {
    background-color: #dce5ef;
    border: 1px solid #b8c6d4;
    border-radius: 5px;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #1ea7e1, stop:1 #56ccf2);
    border-radius: 4px;
}
QScrollBar:vertical {
    background: #e3eaf2;
    width: 12px;
    margin: 2px;
    border-radius: 6px;
}
QScrollBar::handle:vertical {
    background: #b5c4d4;
    min-height: 28px;
    border-radius: 5px;
}
QScrollBar::handle:vertical:hover {
    background: #2ab7eb;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
QScrollBar:horizontal {
    background: #e3eaf2;
    height: 12px;
    margin: 2px;
    border-radius: 6px;
}
QScrollBar::handle:horizontal {
    background: #b5c4d4;
    min-width: 28px;
    border-radius: 5px;
}
QScrollBar::handle:horizontal:hover {
    background: #2ab7eb;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}
QSplitter::handle {
    background-color: #cfd9e4;
    border-radius: 2px;
}
QSplitter::handle:hover {
    background-color: #2ab7eb;
}
"""


def apply_channel_palette(app) -> None:
    app.setStyle("Fusion")
    pal = QPalette()
    pal.setColor(QPalette.ColorRole.Window, QColor("#e6ebf0"))
    pal.setColor(QPalette.ColorRole.WindowText, QColor("#2c3640"))
    pal.setColor(QPalette.ColorRole.Base, QColor("#ffffff"))
    pal.setColor(QPalette.ColorRole.AlternateBase, QColor("#f4f8fc"))
    pal.setColor(QPalette.ColorRole.ToolTipBase, QColor("#ffffff"))
    pal.setColor(QPalette.ColorRole.ToolTipText, QColor("#1e293b"))
    pal.setColor(QPalette.ColorRole.Text, QColor("#24303c"))
    pal.setColor(QPalette.ColorRole.PlaceholderText, QColor("#8596a7"))
    pal.setColor(QPalette.ColorRole.Button, QColor("#eef3f8"))
    pal.setColor(QPalette.ColorRole.ButtonText, QColor("#2f3b47"))
    pal.setColor(QPalette.ColorRole.BrightText, QColor("#ffffff"))
    pal.setColor(QPalette.ColorRole.Highlight, QColor("#2ab7eb"))
    pal.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
    app.setPalette(pal)


class PinstripeBackdrop(QWidget):

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, False)

    def paintEvent(self, event):
        painter = QPainter(self)
        rect = self.rect()

        grad = QLinearGradient(0.0, 0.0, 0.0, float(rect.height()))
        grad.setColorAt(0.0, QColor("#eef2f6"))
        grad.setColorAt(0.6, QColor("#e5ebf1"))
        grad.setColorAt(1.0, QColor("#dae2ea"))
        painter.fillRect(rect, grad)

        pen = QPen(QColor(255, 255, 255, 115))
        pen.setWidth(1)
        painter.setPen(pen)
        h = rect.height()
        w = rect.width()
        for y in range(0, h, 4):
            painter.drawLine(0, y, w, y)


class ChannelTileCard(QFrame):

    clicked = pyqtSignal()

    def __init__(
        self,
        tag_text: str,
        title_text: str,
        subtitle_text: str,
        action_text: str = "Start",
        emblem: str = "scan",
        recessed_slot: bool = False,
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)
        self.emblem = emblem
        self.recessed_slot = recessed_slot
        self._hovered = False

        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumSize(270, 155)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(6)

        top_row = QHBoxLayout()
        self.lbl_tag = QLabel(tag_text)
        if recessed_slot:
            self.lbl_tag.setStyleSheet(
                "background-color: rgba(185, 198, 212, 95); color: #5b6b7c; "
                "font-weight: bold; font-size: 10px; padding: 2px 10px; border-radius: 8px;"
            )
        else:
            self.lbl_tag.setStyleSheet(
                "background-color: #e4f5fd; color: #09699b; border: 1px solid #96dcf8; "
                "font-weight: bold; font-size: 10px; padding: 2px 10px; border-radius: 8px;"
            )
        top_row.addWidget(self.lbl_tag)
        top_row.addStretch()
        layout.addLayout(top_row)

        layout.addStretch(1)

        self.lbl_title = QLabel(title_text)
        if recessed_slot:
            self.lbl_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.lbl_title.setStyleSheet("color: #6b7c8e; font-weight: bold; font-size: 16px; background: transparent;")
        else:
            self.lbl_title.setStyleSheet("color: #23303d; font-weight: bold; font-size: 18px; background: transparent;")
        layout.addWidget(self.lbl_title)

        self.lbl_subtitle = QLabel(subtitle_text)
        self.lbl_subtitle.setWordWrap(True)
        if recessed_slot:
            self.lbl_subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.lbl_subtitle.setStyleSheet("color: #7e8f9f; font-size: 11px; background: transparent;")
        else:
            self.lbl_subtitle.setStyleSheet("color: #596979; font-size: 11px; background: transparent;")
        layout.addWidget(self.lbl_subtitle)

        layout.addStretch(1)

        bottom_row = QHBoxLayout()
        bottom_row.addStretch()
        self.lbl_action = QLabel(action_text)
        self.lbl_action.setStyleSheet(
            "background-color: rgba(255, 255, 255, 210); color: #086494; "
            "border: 1px solid #6ecbf2; border-radius: 10px; padding: 3px 12px; "
            "font-weight: bold; font-size: 11px;"
        )
        bottom_row.addWidget(self.lbl_action)
        layout.addLayout(bottom_row)

        for child_lbl in (self.lbl_tag, self.lbl_title, self.lbl_subtitle, self.lbl_action):
            child_lbl.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)

    def set_subtitle(self, text: str):
        self.lbl_subtitle.setText(text)

    def enterEvent(self, event):
        self._hovered = True
        self.update()
        super().enterEvent(event)

    def leaveEvent(self, event):
        self._hovered = False
        self.update()
        super().leaveEvent(event)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        r = QRectF(self.rect()).adjusted(4.0, 4.0, -4.0, -6.0)
        radius = 22.0

        shadow_rect = r.translated(0.0, 3.0)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(50, 70, 90, 26))
        painter.drawRoundedRect(shadow_rect, radius, radius)

        if self.recessed_slot:
            slot_grad = QLinearGradient(r.topLeft(), r.bottomLeft())
            slot_grad.setColorAt(0.0, QColor("#d9e1e9"))
            slot_grad.setColorAt(1.0, QColor("#e6ecf2"))
            painter.setBrush(slot_grad)
            painter.drawRoundedRect(r, radius, radius)

            clip_path = QPainterPath()
            clip_path.addRoundedRect(r, radius, radius)
            painter.save()
            painter.setClipPath(clip_path)
            line_pen = QPen(QColor(255, 255, 255, 110), 1.0)
            painter.setPen(line_pen)
            y = int(r.top())
            while y < int(r.bottom()):
                painter.drawLine(int(r.left()), y, int(r.right()), y)
                y += 5
            painter.restore()
        else:
            card_grad = QLinearGradient(r.topLeft(), r.bottomLeft())
            if self._hovered:
                card_grad.setColorAt(0.0, QColor("#ffffff"))
                card_grad.setColorAt(0.55, QColor("#f5fcff"))
                card_grad.setColorAt(1.0, QColor("#e1f4fd"))
            else:
                card_grad.setColorAt(0.0, QColor("#ffffff"))
                card_grad.setColorAt(0.55, QColor("#f7fafd"))
                card_grad.setColorAt(1.0, QColor("#eaf0f6"))
            painter.setBrush(card_grad)
            painter.drawRoundedRect(r, radius, radius)

            clip_path = QPainterPath()
            clip_path.addRoundedRect(r, radius, radius)
            painter.save()
            painter.setClipPath(clip_path)
            self._draw_emblem(painter, r)

            gloss_rect = QRectF(r.left(), r.top(), r.width(), r.height() * 0.45)
            gloss_grad = QLinearGradient(gloss_rect.topLeft(), gloss_rect.bottomLeft())
            gloss_grad.setColorAt(0.0, QColor(255, 255, 255, 175))
            gloss_grad.setColorAt(1.0, QColor(255, 255, 255, 0))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(gloss_grad)
            painter.drawRoundedRect(gloss_rect, radius, radius)
            painter.restore()

        painter.setBrush(Qt.BrushStyle.NoBrush)
        if self._hovered:
            outer_glow = QPen(QColor(42, 183, 235, 95), 5.0)
            painter.setPen(outer_glow)
            painter.drawRoundedRect(r, radius, radius)

            main_ring = QPen(QColor("#2ab7eb"), 2.5)
            painter.setPen(main_ring)
            painter.drawRoundedRect(r, radius, radius)
        else:
            bevel = QPen(QColor("#b8c5d3" if not self.recessed_slot else "#c3cfd9"), 2.0)
            painter.setPen(bevel)
            painter.drawRoundedRect(r, radius, radius)

    def _draw_emblem(self, painter: QPainter, r: QRectF):
        cx = r.right() - 62.0
        cy = r.top() + 56.0
        accent = QColor(42, 183, 235, 48 if self._hovered else 30)
        pen = QPen(accent, 2.2)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)

        if self.emblem == "scan":
            painter.drawEllipse(QPointF(cx, cy), 34.0, 34.0)
            painter.drawEllipse(QPointF(cx, cy), 20.0, 20.0)
            painter.drawLine(QPointF(cx - 42.0, cy), QPointF(cx + 42.0, cy))
            painter.drawLine(QPointF(cx, cy - 42.0), QPointF(cx, cy + 42.0))
        elif self.emblem == "layers":
            for idx in range(3):
                off = idx * 10.0
                rect_l = QRectF(cx - 28.0 + off, cy - 26.0 + off, 42.0, 32.0)
                painter.drawRoundedRect(rect_l, 6.0, 6.0)
        elif self.emblem == "vault":
            body = QRectF(cx - 24.0, cy - 8.0, 48.0, 36.0)
            painter.drawRoundedRect(body, 8.0, 8.0)
            painter.drawArc(QRectF(cx - 14.0, cy - 28.0, 28.0, 32.0), 0, 180 * 16)
            painter.drawEllipse(QPointF(cx, cy + 10.0), 5.0, 5.0)
        elif self.emblem == "manual":
            doc = QRectF(cx - 24.0, cy - 28.0, 48.0, 56.0)
            painter.drawRoundedRect(doc, 7.0, 7.0)
            for idx in range(4):
                ly = cy - 14.0 + idx * 11.0
                painter.drawLine(QPointF(cx - 14.0, ly), QPointF(cx + 14.0, ly))
        elif self.emblem == "disc":
            painter.drawEllipse(QPointF(cx, cy), 32.0, 32.0)
            painter.drawEllipse(QPointF(cx, cy), 10.0, 10.0)


class CurvedSystemFooter(QWidget):

    home_clicked = pyqtSignal()
    load_clicked = pyqtSignal()

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setFixedHeight(76)
        self._status_message = "Ready"

        layout = QHBoxLayout(self)
        layout.setContentsMargins(22, 10, 22, 8)
        layout.setSpacing(12)

        self.btn_home = QPushButton("Menu")
        self.btn_home.setObjectName("ShoulderOrb")
        self.btn_home.setFixedSize(148, 44)
        self.btn_home.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_home.clicked.connect(self.home_clicked.emit)
        layout.addWidget(self.btn_home, alignment=Qt.AlignmentFlag.AlignVCenter)

        center_col = QVBoxLayout()
        center_col.setContentsMargins(0, 0, 0, 0)
        center_col.setSpacing(2)

        self.lbl_clock = QLabel()
        self.lbl_clock.setAlignment(Qt.AlignmentFlag.AlignCenter)
        clock_font = QFont("Consolas")
        clock_font.setStyleHint(QFont.StyleHint.Monospace)
        clock_font.setPointSize(16)
        clock_font.setBold(True)
        self.lbl_clock.setFont(clock_font)
        self.lbl_clock.setStyleSheet("color: #556575; letter-spacing: 2px; background: transparent;")
        center_col.addWidget(self.lbl_clock)

        self.lbl_date = QLabel()
        self.lbl_date.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_date.setStyleSheet("color: #465564; font-weight: bold; font-size: 11px; background: transparent;")
        center_col.addWidget(self.lbl_date)

        layout.addLayout(center_col, stretch=1)

        self.btn_load = QPushButton("Load File...")
        self.btn_load.setObjectName("ShoulderOrb")
        self.btn_load.setFixedSize(148, 44)
        self.btn_load.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_load.clicked.connect(self.load_clicked.emit)
        layout.addWidget(self.btn_load, alignment=Qt.AlignmentFlag.AlignVCenter)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh_clock)
        self._timer.start(1000)
        self._refresh_clock()

    def set_status_text(self, message: str):
        self._status_message = message.strip() or "Ready"
        self._refresh_clock()

    def _refresh_clock(self):
        now = QDateTime.currentDateTime()
        self.lbl_clock.setText(now.toString("HH : mm"))
        date_part = now.toString("ddd MM/dd")
        self.lbl_date.setText(f"{date_part}   |   {self._status_message}")

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        w = float(self.width())
        h = float(self.height())
        wing_w = 190.0
        curve_span = 55.0
        wing_top = 6.0
        shelf_top = 34.0

        path = QPainterPath()
        path.moveTo(0.0, h)
        path.lineTo(0.0, wing_top)
        path.lineTo(wing_w, wing_top)
        path.cubicTo(
            wing_w + curve_span * 0.45,
            wing_top,
            wing_w + curve_span * 0.55,
            shelf_top,
            wing_w + curve_span,
            shelf_top,
        )
        right_shelf_end = max(wing_w + curve_span, w - wing_w - curve_span)
        path.lineTo(right_shelf_end, shelf_top)
        path.cubicTo(
            w - wing_w - curve_span * 0.55,
            shelf_top,
            w - wing_w - curve_span * 0.45,
            wing_top,
            w - wing_w,
            wing_top,
        )
        path.lineTo(w, wing_top)
        path.lineTo(w, h)
        path.closeSubpath()

        grad = QLinearGradient(0.0, wing_top, 0.0, h)
        grad.setColorAt(0.0, QColor("#f4f7fa"))
        grad.setColorAt(0.45, QColor("#e1e8f0"))
        grad.setColorAt(1.0, QColor("#cfd9e4"))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(grad)
        painter.drawPath(path)

        trim_path = QPainterPath()
        trim_path.moveTo(0.0, wing_top)
        trim_path.lineTo(wing_w, wing_top)
        trim_path.cubicTo(
            wing_w + curve_span * 0.45,
            wing_top,
            wing_w + curve_span * 0.55,
            shelf_top,
            wing_w + curve_span,
            shelf_top,
        )
        trim_path.lineTo(right_shelf_end, shelf_top)
        trim_path.cubicTo(
            w - wing_w - curve_span * 0.55,
            shelf_top,
            w - wing_w - curve_span * 0.45,
            wing_top,
            w - wing_w,
            wing_top,
        )
        trim_path.lineTo(w, wing_top)

        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.setPen(QPen(QColor("#2ab7eb"), 2.5))
        painter.drawPath(trim_path)
