from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import QDialog, QLabel, QScrollArea, QVBoxLayout


class ImageViewerDialog(QDialog):
    def __init__(self, container, entry, parent=None):
        super().__init__(parent)
        self.setWindowTitle(entry.name)
        self.resize(800, 600)

        label = QLabel()
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        data = bytes(container.read_at(entry.file_id, 0, entry.size))
        pixmap = QPixmap()
        if pixmap.loadFromData(data):
            label.setPixmap(pixmap)
        else:
            label.setText("Не удалось декодировать изображение.")

        scroll = QScrollArea()
        scroll.setWidget(label)
        scroll.setWidgetResizable(True)

        layout = QVBoxLayout(self)
        layout.addWidget(scroll)
