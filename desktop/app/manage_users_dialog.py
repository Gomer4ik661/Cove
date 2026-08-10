from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
)

ROLE_LABELS = {
    "admin": "Администратор",
    "read_write": "Чтение и запись",
    "read_only": "Только чтение",
}
ROLE_VALUES = list(ROLE_LABELS.keys())


class ManageUsersDialog(QDialog):
    """Список пользователей + смена роли/удаление — ROADMAP.md Фаза 12.

    До этого диалога `remove_user()`/`set_user_role()` существовали только в
    Core: `remove_user` с Фазы 3/4, но ни разу не вызывался ни одной кнопкой."""

    def __init__(self, container, parent=None):
        super().__init__(parent)
        self._container = container
        self.setWindowTitle("Пользователи")
        self.setMinimumSize(420, 320)

        self._list = QListWidget()
        self._list.currentItemChanged.connect(self._on_selection_changed)

        self._role_combo = QComboBox()
        for value in ROLE_VALUES:
            self._role_combo.addItem(ROLE_LABELS[value], userData=value)

        apply_role_btn = QPushButton("Сменить роль")
        apply_role_btn.clicked.connect(self._apply_role)

        remove_btn = QPushButton("Удалить пользователя")
        remove_btn.clicked.connect(self._remove_selected)

        role_row = QHBoxLayout()
        role_row.addWidget(QLabel("Роль:"))
        role_row.addWidget(self._role_combo, stretch=1)
        role_row.addWidget(apply_role_btn)

        layout = QVBoxLayout(self)
        layout.addWidget(self._list, stretch=1)
        layout.addLayout(role_row)
        layout.addWidget(remove_btn)

        self._reload()

    def _reload(self) -> None:
        self._list.clear()
        for username, role in self._container.list_users():
            label = f"{username} — {ROLE_LABELS.get(role, role)}"
            item = QListWidgetItem(label, self._list)
            item.setData(Qt.ItemDataRole.UserRole, (username, role))
        if self._list.count():
            self._list.setCurrentRow(0)

    def _selected(self):
        item = self._list.currentItem()
        return item.data(Qt.ItemDataRole.UserRole) if item else None

    def _on_selection_changed(self, current, _previous) -> None:
        data = current.data(Qt.ItemDataRole.UserRole) if current else None
        if data is None:
            return
        _username, role = data
        if role in ROLE_VALUES:
            self._role_combo.setCurrentIndex(ROLE_VALUES.index(role))

    def _apply_role(self) -> None:
        selected = self._selected()
        if selected is None:
            return
        username, current_role = selected
        new_role = self._role_combo.currentData()
        if new_role == current_role:
            return
        try:
            self._container.set_user_role(username, new_role)
        except Exception as exc:  # noqa: BLE001 — граница UI
            QMessageBox.critical(self, "Cove", f"Не удалось сменить роль: {exc}")
        else:
            self._reload()

    def _remove_selected(self) -> None:
        selected = self._selected()
        if selected is None:
            return
        username, _role = selected
        question = f"Удалить пользователя «{username}»? Это действие необратимо."
        if QMessageBox.question(self, "Cove", question) != QMessageBox.StandardButton.Yes:
            return
        try:
            self._container.remove_user(username)
        except Exception as exc:  # noqa: BLE001 — граница UI
            QMessageBox.critical(self, "Cove", f"Не удалось удалить пользователя: {exc}")
        else:
            self._reload()
