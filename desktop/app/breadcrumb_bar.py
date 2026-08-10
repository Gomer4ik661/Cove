from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QWidget


class BreadcrumbBar(QWidget):
    """Кликабельная цепочка "Раздел / Папка / Подпапка" — ROADMAP.md Фаза 11.
    Последний сегмент (текущее место) не кликабелен, остальные — переходят
    на соответствующий уровень через переданный колбэк."""

    def __init__(self, on_segment_clicked, parent=None):
        super().__init__(parent)
        self._on_segment_clicked = on_segment_clicked
        self._layout = QHBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(4)

    def set_path(self, segments) -> None:
        """segments: список (label, value) от корня к текущему месту —
        value передаётся в колбэк как есть при клике на этот сегмент."""
        while self._layout.count():
            item = self._layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

        for i, (label, value) in enumerate(segments):
            if i > 0:
                self._layout.addWidget(QLabel("/"))
            is_current = i == len(segments) - 1
            btn = QPushButton(label)
            btn.setFlat(True)
            if is_current:
                btn.setEnabled(False)
            else:
                btn.setCursor(Qt.CursorShape.PointingHandCursor)
                btn.clicked.connect(lambda _checked=False, v=value: self._on_segment_clicked(v))
            self._layout.addWidget(btn)

        self._layout.addStretch(1)
