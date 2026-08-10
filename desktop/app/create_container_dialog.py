from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
)


class CreateContainerDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Создать хранилище Cove")
        self.setMinimumWidth(420)

        self._path_edit = QLineEdit()
        browse_btn = QPushButton("Обзор…")
        browse_btn.clicked.connect(self._browse)
        path_row = QHBoxLayout()
        path_row.addWidget(self._path_edit)
        path_row.addWidget(browse_btn)

        self._username_edit = QLineEdit()
        self._password_edit = QLineEdit()
        self._password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._confirm_edit = QLineEdit()
        self._confirm_edit.setEchoMode(QLineEdit.EchoMode.Password)

        form = QFormLayout()
        form.addRow("Файл хранилища (.slr):", path_row)
        form.addRow("Имя администратора:", self._username_edit)
        form.addRow("Пароль:", self._password_edit)
        form.addRow("Повтор пароля:", self._confirm_edit)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def _browse(self) -> None:
        # DontUseNativeDialog — см. main_window.py: нативный диалог через
        # xdg-desktop-portal на некоторых системах ненадёжен.
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Новое хранилище",
            "",
            "Cove Storage (*.slr)",
            "",
            QFileDialog.Option.DontUseNativeDialog,
        )
        if path:
            if not path.endswith(".slr"):
                path += ".slr"
            self._path_edit.setText(path)

    def _on_accept(self) -> None:
        if not self._path_edit.text().strip():
            QMessageBox.warning(self, "Cove", "Выберите путь к файлу хранилища.")
            return
        if not self._username_edit.text().strip():
            QMessageBox.warning(self, "Cove", "Введите имя администратора.")
            return
        if not self._password_edit.text():
            QMessageBox.warning(self, "Cove", "Введите пароль.")
            return
        if self._password_edit.text() != self._confirm_edit.text():
            QMessageBox.warning(self, "Cove", "Пароли не совпадают.")
            return
        self.accept()

    def path(self) -> str:
        return self._path_edit.text().strip()

    def username(self) -> str:
        return self._username_edit.text().strip()

    def password(self) -> str:
        return self._password_edit.text()
