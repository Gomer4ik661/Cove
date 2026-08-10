from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QTextEdit,
    QVBoxLayout,
)

import cove_core_py as core


class LoginDialog(QDialog):
    """`attempt_limit` — сколько неудачных попыток разрешено в рамках ОДНОГО
    открытия этого диалога, 0 — без лимита. Считается только здесь, в
    памяти GUI: Core на этот момент ещё не знает DEK и физически не может
    зашифровать счётчик неудачных попыток внутри контейнера (ROADMAP.md
    Фаза 4/12) — так что переоткрытие диалога честно сбрасывает счётчик,
    это не постоянная защита от подбора, а сдерживающий фактор в рамках сессии."""

    def __init__(self, locked: "core.LockedContainer", parent=None, attempt_limit: int = 0):
        super().__init__(parent)
        self._locked = locked
        self._container = None
        self._attempt_limit = attempt_limit
        self._failed_attempts = 0

        self.setWindowTitle("Вход в хранилище")
        self.setMinimumWidth(380)

        # Логин — свободный ввод, а не выпадающий список: и это буквально
        # "спросить логин и пароль" (обычная форма входа), и заодно не
        # показывает список существующих пользователей на экране блокировки
        # тому, кто просто проходит мимо.
        self._username_edit = QLineEdit()
        self._username_edit.setPlaceholderText("Имя пользователя")
        usernames = locked.list_usernames()
        if len(usernames) == 1:
            self._username_edit.setText(usernames[0])  # единственный юзер — удобно подставить

        self._password_edit = QLineEdit()
        self._password_edit.setEchoMode(QLineEdit.EchoMode.Password)

        self._recovery_edit = QTextEdit()
        self._recovery_edit.setPlaceholderText("12 слов через пробел")
        self._recovery_edit.setFixedHeight(70)
        self._recovery_edit.hide()

        self._use_recovery = QCheckBox("Войти по recovery-фразе вместо пароля")
        self._use_recovery.stateChanged.connect(self._toggle_mode)

        self._username_label = QLabel("Пользователь:")
        self._password_label = QLabel("Пароль:")

        form = QFormLayout()
        form.addRow(self._username_label, self._username_edit)
        form.addRow(self._password_label, self._password_edit)
        form.addRow("", self._recovery_edit)

        self._status_label = QLabel("")
        self._status_label.setWordWrap(True)

        self._buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self._buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Войти")
        self._buttons.accepted.connect(self._try_unlock)
        self._buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(self._use_recovery)
        layout.addWidget(self._status_label)
        layout.addWidget(self._buttons)

    def _toggle_mode(self) -> None:
        recovery_mode = self._use_recovery.isChecked()
        self._username_edit.setEnabled(not recovery_mode)
        self._password_edit.setEnabled(not recovery_mode)
        self._password_edit.setVisible(not recovery_mode)
        self._password_label.setVisible(not recovery_mode)
        self._recovery_edit.setVisible(recovery_mode)

    def _try_unlock(self) -> None:
        # Не полагаемся только на визуально выключенные поля — проверяем
        # лимит явно, здесь же, а не только через setEnabled(False) в
        # _register_failed_attempt(). Так поведение верно независимо от
        # того, как вызван метод (клик по кнопке, Enter, программно).
        if self._attempt_limit and self._failed_attempts >= self._attempt_limit:
            return
        try:
            if self._use_recovery.isChecked():
                phrase = self._recovery_edit.toPlainText().strip()
                self._container = self._locked.unlock_with_recovery(phrase)
            else:
                username = self._username_edit.text().strip()
                password = self._password_edit.text()
                self._container = self._locked.unlock(username, password)
        except core.CoveAuthError:
            self._register_failed_attempt()
            return
        except Exception as exc:  # noqa: BLE001 — граница UI: показать любую ошибку core пользователю
            QMessageBox.critical(self, "Cove", f"Не удалось открыть хранилище: {exc}")
            return
        self.accept()

    def _register_failed_attempt(self) -> None:
        self._failed_attempts += 1
        if self._attempt_limit and self._failed_attempts >= self._attempt_limit:
            self._status_label.setText(
                f"Превышен лимит попыток ({self._attempt_limit}). "
                "Закройте окно и попробуйте снова."
            )
            self._buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(False)
            self._username_edit.setEnabled(False)
            self._password_edit.setEnabled(False)
            self._recovery_edit.setEnabled(False)
            self._use_recovery.setEnabled(False)
        else:
            remaining = (
                f" Осталось попыток: {self._attempt_limit - self._failed_attempts}."
                if self._attempt_limit
                else ""
            )
            self._status_label.setText(f"Неверный пароль или recovery-фраза.{remaining}")

    def container(self):
        return self._container
