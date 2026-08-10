from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLineEdit,
    QMessageBox,
    QVBoxLayout,
)

ROLE_LABELS = {
    "admin": "Администратор",
    "read_write": "Чтение и запись",
    "read_only": "Только чтение",
}


class AddUserDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Добавить пользователя")
        self.setMinimumWidth(360)

        self._username_edit = QLineEdit()
        self._password_edit = QLineEdit()
        self._password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._role_combo = QComboBox()
        for value, label in ROLE_LABELS.items():
            self._role_combo.addItem(label, userData=value)
        self._role_combo.setCurrentIndex(1)  # "Чтение и запись" по умолчанию

        form = QFormLayout()
        form.addRow("Имя пользователя:", self._username_edit)
        form.addRow("Пароль:", self._password_edit)
        form.addRow("Роль:", self._role_combo)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def _on_accept(self) -> None:
        if not self._username_edit.text().strip() or not self._password_edit.text():
            QMessageBox.warning(self, "Cove", "Заполните имя пользователя и пароль.")
            return
        self.accept()

    def username(self) -> str:
        return self._username_edit.text().strip()

    def password(self) -> str:
        return self._password_edit.text()

    def role(self) -> str:
        return self._role_combo.currentData()
