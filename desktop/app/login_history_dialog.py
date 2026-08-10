from datetime import datetime

from PySide6.QtWidgets import QDialog, QListWidget, QListWidgetItem, QVBoxLayout


class LoginHistoryDialog(QDialog):
    """Просмотр журнала входов — ROADMAP.md Фаза 4/12.

    `Container.login_history()` в Core готов и покрыт тестами с Фазы 4, но
    до этого диалога в GUI его никто не вызывал — посмотреть журнал было
    просто негде."""

    def __init__(self, container, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Журнал входов")
        self.setMinimumSize(420, 360)

        entries = list(container.login_history())
        entries.reverse()  # самые свежие сверху

        listw = QListWidget()
        if entries:
            for entry in entries:
                when = datetime.fromtimestamp(entry.timestamp).strftime("%d.%m.%Y %H:%M:%S")
                status = "успешно" if entry.success else "неудачно"
                QListWidgetItem(f"{when} — {entry.username} ({status})", listw)
        else:
            QListWidgetItem("Журнал пуст.", listw)

        layout = QVBoxLayout(self)
        layout.addWidget(listw)
