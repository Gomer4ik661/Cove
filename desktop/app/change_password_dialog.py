from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLineEdit,
    QMessageBox,
    QVBoxLayout,
)


class ChangePasswordDialog(QDialog):
    def __init__(self, username: str, parent=None):
        super().__init__(parent)
        self._username = username
        self.setWindowTitle(f"Смена пароля — {username}")
        self.setMinimumWidth(360)

        self._old_edit = QLineEdit()
        self._old_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._new_edit = QLineEdit()
        self._new_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._confirm_edit = QLineEdit()
        self._confirm_edit.setEchoMode(QLineEdit.EchoMode.Password)

        form = QFormLayout()
        form.addRow("Текущий пароль:", self._old_edit)
        form.addRow("Новый пароль:", self._new_edit)
        form.addRow("Повтор нового пароля:", self._confirm_edit)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def _on_accept(self) -> None:
        if not self._old_edit.text() or not self._new_edit.text():
            QMessageBox.warning(self, "Cove", "Заполните все поля.")
            return
        if self._new_edit.text() != self._confirm_edit.text():
            QMessageBox.warning(self, "Cove", "Новые пароли не совпадают.")
            return
        self.accept()

    def old_password(self) -> str:
        return self._old_edit.text()

    def new_password(self) -> str:
        return self._new_edit.text()
