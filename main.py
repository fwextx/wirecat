import sys
import socket
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QScrollArea)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QFont
from sniffer import start_sniffing, packet_queue
from icon_utils import get_process_icon

button_style = """
QPushButton {
    background-color: #333;
    border: none;
    color: white;
    font-weight: bold;
    border-radius: 15px;
    padding: 6px 14px;
    margin: 0 6px;
}
QPushButton:hover {
    background-color: #555;
}
QPushButton:checked {
    background-color: #1e90ff;
}
"""

window_btn_style = """
QPushButton {
    background-color: #222;
    border: none;
    color: white;
    font-weight: bold;
    font-size: 14px;
}
QPushButton:hover {
    background-color: #444;
}
"""

class TitleBar(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(30)
        self.setStyleSheet("background-color: #121212; color: white;")
        self.layout = QHBoxLayout(self)
        self.layout.setContentsMargins(10, 0, 10, 0)

        self.title = QLabel("Wirecat - Live Packet Viewer")
        self.title.setStyleSheet("""
            font-weight: bold;
            background-color: #121212;
            padding-left: 5px;
            padding-right: 5px;
        """)
        self.layout.addWidget(self.title)

        self.layout.addStretch()

        self.minBtn = QPushButton("_")
        self.minBtn.setFixedSize(30, 24)
        self.minBtn.setStyleSheet(window_btn_style)
        self.minBtn.clicked.connect(parent.showMinimized)
        self.layout.addWidget(self.minBtn)

        self.maxBtn = QPushButton("⬜")
        self.maxBtn.setFixedSize(30, 24)
        self.maxBtn.setStyleSheet(window_btn_style)
        self.maxBtn.clicked.connect(self.toggle_max_restore)
        self.layout.addWidget(self.maxBtn)

        self.closeBtn = QPushButton("X")
        self.closeBtn.setFixedSize(30, 24)
        self.closeBtn.setStyleSheet(window_btn_style)
        self.closeBtn.clicked.connect(parent.close)
        self.layout.addWidget(self.closeBtn)

        self._mouse_pos = None
        self.setCursor(Qt.OpenHandCursor)
        self.parent_window = parent

    def toggle_max_restore(self):
        if self.parent_window.isMaximized():
            self.parent_window.showNormal()
            self.maxBtn.setText("⬜")
        else:
            self.parent_window.showMaximized()
            self.maxBtn.setText("❐")

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.setCursor(Qt.ClosedHandCursor)
            self._mouse_pos = event.globalPos() - self.window().frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event):
        if event.buttons() == Qt.LeftButton and self._mouse_pos is not None:
            self.window().move(event.globalPos() - self._mouse_pos)
            event.accept()

    def mouseReleaseEvent(self, event):
        self.setCursor(Qt.OpenHandCursor)
        self._mouse_pos = None
        event.accept()

class PacketBubble(QWidget):
    expanded_changed = pyqtSignal(bool)

    def __init__(self, proto, src_ip, src_port, dst_ip, dst_port, raw_bytes=None, icon_pixmap=None, app_name="?"):
        super().__init__()
        self.is_expanded = False
        self.setFixedHeight(60)
        self.setStyleSheet("""
            QWidget {
                background-color: #222;
                border-radius: 12px;
                padding: 10px;
                color: white;
            }
            QLabel {
                color: white;
                font-size: 12px;
                font-family: monospace;
            }
        """)

        self.layout = QHBoxLayout()
        self.layout.setContentsMargins(12, 8, 12, 8)

        if icon_pixmap and not icon_pixmap.isNull():
            self.icon_label = QLabel()
            self.icon_label.setPixmap(icon_pixmap.scaled(32, 32, Qt.KeepAspectRatio, Qt.SmoothTransformation))
            self.layout.addWidget(self.icon_label)
        else:
            fallback_text = (app_name[:2] if app_name else "?").upper()
            self.icon_label = QLabel(fallback_text)
            self.icon_label.setFixedSize(32, 32)
            self.icon_label.setAlignment(Qt.AlignCenter)
            self.icon_label.setStyleSheet("""
                QLabel {
                    background-color: #555;
                    border-radius: 16px;
                    color: white;
                    font-weight: bold;
                    font-size: 13px;
                }
            """)
            self.layout.addWidget(self.icon_label)

        self.text_layout = QVBoxLayout()
        self.text_layout.setSpacing(2)

        display_name = app_name.capitalize() if app_name and app_name != "?" else "Unknown"
        self.title_label = QLabel(f"[{display_name}] - [{proto}] - {src_ip}:{src_port} → {dst_ip}:{dst_port}")
        self.title_label.setFont(QFont("Arial", 10, QFont.Bold))
        self.text_layout.addWidget(self.title_label)

        self.details_label = QLabel()
        self.details_label.setFont(QFont("Courier New", 9))
        self.details_label.setStyleSheet("color: #aaa;")
        self.details_label.setVisible(False)
        self.text_layout.addWidget(self.details_label)

        if raw_bytes:
            hex_str = ""
            for i in range(0, len(raw_bytes), 16):
                chunk = raw_bytes[i:i+16]
                hex_bytes = ' '.join(f"{b:02X}" for b in chunk)
                ascii_bytes = ''.join((chr(b) if 32 <= b <= 126 else '.') for b in chunk)
                hex_str += f"{i:04X}  {hex_bytes:<48}  {ascii_bytes}\n"

            details_text = (
                f"Protocol: {proto}\n"
                f"Source IP: {src_ip}\n"
                f"Source Port: {src_port}\n"
                f"Destination IP: {dst_ip}\n"
                f"Destination Port: {dst_port}\n"
                f"App Name: {display_name}\n\n"
                f"Packet Information:\n{hex_str}"
            )
            self.details_label.setText(details_text)
        else:
            self.details_label.setText("No raw data available.")

        self.layout.addLayout(self.text_layout)
        self.setLayout(self.layout)

        self.setCursor(Qt.PointingHandCursor)

    def mousePressEvent(self, event):
        self.is_expanded = not self.is_expanded
        self.details_label.setVisible(self.is_expanded)
        if self.is_expanded:
            self.setFixedHeight(self.sizeHint().height())
        else:
            self.setFixedHeight(60)
        self.expanded_changed.emit(self.is_expanded)
        super().mousePressEvent(event)

class PacketViewer(QMainWindow):
    MARGIN = 8  # Resize margin in pixels

    def __init__(self):
        super().__init__()

        self.paused = False
        self.filter_mode = "all"  # all, sending, receiving
        self.setWindowTitle("Wirecat")
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.Window)
        self.setGeometry(100, 100, 900, 650)
        self.setMinimumSize(400, 300)
        self.setMaximumSize(16777215, 16777215)

        self._pressed = False
        self._press_pos = None
        self._resize_dir = None

        mainWidget = QWidget()
        mainLayout = QVBoxLayout()
        mainLayout.setContentsMargins(5, 5, 5, 5)
        mainWidget.setLayout(mainLayout)
        self.setCentralWidget(mainWidget)

        self.titleBar = TitleBar(self)
        mainLayout.addWidget(self.titleBar)

        filterWidget = QWidget()
        filterLayout = QHBoxLayout()
        filterLayout.setContentsMargins(0, 5, 0, 5)
        filterLayout.setSpacing(0)
        filterWidget.setLayout(filterLayout)

        self.allBtn = QPushButton("All")
        self.sendingBtn = QPushButton("Sending")
        self.receivingBtn = QPushButton("Receiving")

        for btn in (self.allBtn, self.sendingBtn, self.receivingBtn):
            btn.setCheckable(True)
            btn.setStyleSheet(button_style)
            btn.setFixedHeight(32)
            filterLayout.addWidget(btn)

        self.allBtn.setChecked(True)

        self.allBtn.clicked.connect(lambda: self.set_filter("all"))
        self.sendingBtn.clicked.connect(lambda: self.set_filter("sending"))
        self.receivingBtn.clicked.connect(lambda: self.set_filter("receiving"))

        mainLayout.addWidget(filterWidget)

        self.scrollArea = QScrollArea()
        self.scrollArea.setWidgetResizable(True)
        self.scrollArea.setStyleSheet("QScrollArea { background-color: #121212; border: none; }")

        self.bubbleContainer = QWidget()
        self.bubbleLayout = QVBoxLayout()
        self.bubbleLayout.setAlignment(Qt.AlignTop)
        self.bubbleContainer.setLayout(self.bubbleLayout)

        self.scrollArea.setWidget(self.bubbleContainer)
        mainLayout.addWidget(self.scrollArea)

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_packets)
        self.timer.start(200)

        start_sniffing()

        self.local_ips = self.get_local_ips()

        self.setMouseTracking(True)

    def get_local_ips(self):
        ips = set()
        hostname = socket.gethostname()
        try:
            for info in socket.getaddrinfo(hostname, None):
                ip = info[4][0]
                if ip != "127.0.0.1" and not ip.startswith("fe80"):
                    ips.add(ip)
        except Exception:
            pass
        ips.add("127.0.0.1")
        ips.add("::1")
        return ips

    def clear_bubbles(self):
        while self.bubbleLayout.count():
            item = self.bubbleLayout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()

    def set_filter(self, mode):
        self.clear_bubbles()
        self.filter_mode = mode
        self.allBtn.setChecked(mode == "all")
        self.sendingBtn.setChecked(mode == "sending")
        self.receivingBtn.setChecked(mode == "receiving")

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._pressed = True
            self._press_pos = event.globalPos()
            self._resize_dir = self._get_resize_direction(event.pos())
            event.accept()
        else:
            super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        self._pressed = False
        self._resize_dir = None
        self.setCursor(Qt.ArrowCursor)
        super().mouseReleaseEvent(event)

    def mouseMoveEvent(self, event):
        pos = event.pos()
        if self._pressed and self._resize_dir:
            self._resize_window(event.globalPos())
            event.accept()
            return

        cursor = self._cursor_for_position(pos)
        self.setCursor(cursor)
        super().mouseMoveEvent(event)

    def _get_resize_direction(self, pos):
        rect = self.rect()
        x, y = pos.x(), pos.y()
        margin = self.MARGIN

        left = x <= margin
        right = x >= rect.width() - margin
        top = y <= margin
        bottom = y >= rect.height() - margin

        if top and left:
            return "top_left"
        elif top and right:
            return "top_right"
        elif bottom and left:
            return "bottom_left"
        elif bottom and right:
            return "bottom_right"
        elif left:
            return "left"
        elif right:
            return "right"
        elif top:
            return "top"
        elif bottom:
            return "bottom"
        else:
            return None

    def _cursor_for_position(self, pos):
        direction = self._get_resize_direction(pos)
        if direction in ("top_left", "bottom_right"):
            return Qt.SizeFDiagCursor
        elif direction in ("top_right", "bottom_left"):
            return Qt.SizeBDiagCursor
        elif direction in ("left", "right"):
            return Qt.SizeHorCursor
        elif direction in ("top", "bottom"):
            return Qt.SizeVerCursor
        else:
            return Qt.ArrowCursor

    def _resize_window(self, global_pos):
        if not self._resize_dir:
            return

        diff = global_pos - self._press_pos
        geom = self.geometry()

        min_width = self.minimumWidth()
        min_height = self.minimumHeight()

        left = geom.left()
        top = geom.top()
        right = geom.right()
        bottom = geom.bottom()

        if "left" in self._resize_dir:
            new_left = left + diff.x()
            if new_left < right - min_width:
                geom.setLeft(new_left)
            else:
                geom.setLeft(right - min_width)

        if "right" in self._resize_dir:
            new_right = right + diff.x()
            if new_right > left + min_width:
                geom.setRight(new_right)
            else:
                geom.setRight(left + min_width)

        if "top" in self._resize_dir:
            new_top = top + diff.y()
            if new_top < bottom - min_height:
                geom.setTop(new_top)
            else:
                geom.setTop(bottom - min_height)

        if "bottom" in self._resize_dir:
            new_bottom = bottom + diff.y()
            if new_bottom > top + min_height:
                geom.setBottom(new_bottom)
            else:
                geom.setBottom(top + min_height)

        self.setGeometry(geom)
        self._press_pos = global_pos

    def update_packets(self):
        if self.paused:
            return
        try:
            while not packet_queue.empty():
                proto, src_ip, src_port, dst_ip, dst_port, raw_bytes = packet_queue.get()

                if self.filter_mode == "sending":
                    if src_ip not in self.local_ips:
                        continue
                elif self.filter_mode == "receiving":
                    if dst_ip not in self.local_ips:
                        continue

                pixmap, app_name = get_process_icon(src_ip, src_port)
                if pixmap is not None and pixmap.isNull():
                    pixmap = None

                bubble = PacketBubble(proto, src_ip, src_port, dst_ip, dst_port,
                                      raw_bytes=raw_bytes,
                                      icon_pixmap=pixmap, app_name=app_name)
                bubble.expanded_changed.connect(self.on_bubble_expanded_changed)

                self.bubbleLayout.insertWidget(0, bubble)

                count = self.bubbleLayout.count()
                if count > 200:
                    for _ in range(100):
                        item = self.bubbleLayout.takeAt(count - 1)
                        if item:
                            w = item.widget()
                            if w:
                                w.deleteLater()
                        count -= 1
        except Exception as e:
            print("[update_packets crash]", e)

    def on_bubble_expanded_changed(self, is_expanded):
        self.paused = is_expanded

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PacketViewer()

    dark_stylesheet = """
    QWidget {
        background-color: #121212;
        color: white;
    }
    QScrollBar:vertical {
        background: transparent;
        width: 0px;
        margin: 0;
        border: none;
    }

    QScrollBar::handle:vertical {
        background: transparent;
        min-height: 0px;
        border-radius: 0px;
    }
    QPushButton {
        background-color: #222;
        border: none;
        color: white;
        font-weight: bold;
    }
    QPushButton:hover {
        background-color: #444;
    }
    """
    app.setStyleSheet(dark_stylesheet)
    window.show()
    sys.exit(app.exec_())
