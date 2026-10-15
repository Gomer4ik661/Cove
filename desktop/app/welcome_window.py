from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

import cove_core_py as core

from . import config as config_module
from . import i18n
from .recovery_phrase_dialog import RecoveryPhraseDialog


class WelcomeWindow(QMainWindow):
    """Единственная точка входа в приложение — единственный путь к
    хранилищу (config.default_container_path()), пользователь его никогда
    не выбирает, по образцу Android (storage/ContainerRegistry.kt:
    filesDir/containers/). Раньше здесь был экран "Создать"/"Открыть
    хранилище" с диалогом выбора произвольного .slr-файла — по прямой
    просьбе пользователя убран: если хранилища ещё нет, сразу форма
    создания администратора; если есть — сразу форма входа."""

    def __init__(self, app, settings: dict, on_unlocked):
        super().__init__()
        self._app = app
        self._settings = settings
        self._on_unlocked = on_unlocked
        self._path = config_module.default_container_path()
        self._locked = None
        self._failed_attempts = 0

        self.setWindowTitle(i18n.tr("Cove"))
        self.resize(420, 320)

        central = QWidget()
        self.setCentralWidget(central)
        self._layout = QVBoxLayout(central)

        if self._path.exists():
            self._build_login_form()
        else:
            self._build_create_form()

    # ---------------------------------------------------------------- создание

    def _build_create_form(self) -> None:
        title = QLabel(i18n.tr("Новое хранилище Cove"))
        title_font = title.font()
        title_font.setPointSize(20)
        title.setFont(title_font)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._username_edit = QLineEdit()
        self._password_edit = QLineEdit()
        self._password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._confirm_edit = QLineEdit()
        self._confirm_edit.setEchoMode(QLineEdit.EchoMode.Password)

        form = QFormLayout()
        form.addRow("Имя администратора:", self._username_edit)
        form.addRow("Пароль:", self._password_edit)
        form.addRow("Повтор пароля:", self._confirm_edit)

        self._status_label = QLabel("")
        self._status_label.setWordWrap(True)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Создать")
        buttons.accepted.connect(self._create_container)

        self._layout.addStretch()
        self._layout.addWidget(title)
        self._layout.addSpacing(16)
        self._layout.addLayout(form)
        self._layout.addWidget(self._status_label)
        self._layout.addWidget(buttons)
        self._layout.addStretch()

    def _create_container(self) -> None:
        username = self._username_edit.text().strip()
        password = self._password_edit.text()
        confirm = self._confirm_edit.text()
        if not username:
            self._status_label.setText("Введите имя администратора.")
            return
        if not password:
            self._status_label.setText("Введите пароль.")
            return
        if password != confirm:
            self._status_label.setText("Пароли не совпадают.")
            return

        try:
            container, recovery_phrase = core.Container.create(
                str(self._path), username, password
            )
        except Exception as exc:  # noqa: BLE001 — граница UI
            QMessageBox.critical(self, "Cove", f"Не удалось создать хранилище: {exc}")
            return

        RecoveryPhraseDialog(recovery_phrase, self).exec()
        self._on_unlocked(container, str(self._path))

    # -------------------------------------------------------------------- вход

    def _build_login_form(self) -> None:
        try:
            self._locked = core.LockedContainer.open(str(self._path))
        except Exception as exc:  # noqa: BLE001 — граница UI
            error_label = QLabel(f"Не удалось открыть файл хранилища: {exc}")
            error_label.setWordWrap(True)
            self._layout.addStretch()
            self._layout.addWidget(error_label)
            self._layout.addStretch()
            return

        title = QLabel(i18n.tr("Вход в Cove"))
        title_font = title.font()
        title_font.setPointSize(20)
        title.setFont(title_font)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._username_edit = QLineEdit()
        self._username_edit.setPlaceholderText("Имя пользователя")
        usernames = self._locked.list_usernames()
        if len(usernames) == 1:
            self._username_edit.setText(usernames[0])

        self._password_edit = QLineEdit()
        self._password_edit.setEchoMode(QLineEdit.EchoMode.Password)

        self._recovery_edit = QTextEdit()
        self._recovery_edit.setPlaceholderText("12 слов через пробел")
        self._recovery_edit.setFixedHeight(70)
        self._recovery_edit.hide()

        self._use_recovery = QCheckBox("Войти по recovery-фразе вместо пароля")
        self._use_recovery.stateChanged.connect(self._toggle_recovery_mode)

        self._username_label = QLabel("Пользователь:")
        self._password_label = QLabel("Пароль:")

        form = QFormLayout()
        form.addRow(self._username_label, self._username_edit)
        form.addRow(self._password_label, self._password_edit)
        form.addRow("", self._recovery_edit)

        self._status_label = QLabel("")
        self._status_label.setWordWrap(True)

        self._login_buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        self._login_buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Войти")
        self._login_buttons.accepted.connect(self._try_unlock)

        self._layout.addStretch()
        self._layout.addWidget(title)
        self._layout.addSpacing(16)
        self._layout.addLayout(form)
        self._layout.addWidget(self._use_recovery)
        self._layout.addWidget(self._status_label)
        self._layout.addWidget(self._login_buttons)
        self._layout.addStretch()

    def _toggle_recovery_mode(self) -> None:
        recovery_mode = self._use_recovery.isChecked()
        self._username_edit.setEnabled(not recovery_mode)
        self._password_edit.setEnabled(not recovery_mode)
        self._password_edit.setVisible(not recovery_mode)
        self._password_label.setVisible(not recovery_mode)
        self._recovery_edit.setVisible(recovery_mode)

    def _try_unlock(self) -> None:
        attempt_limit = self._settings.get("login_attempt_limit", 0)
        if attempt_limit and self._failed_attempts >= attempt_limit:
            return
        try:
            if self._use_recovery.isChecked():
                phrase = self._recovery_edit.toPlainText().strip()
                container = self._locked.unlock_with_recovery(phrase)
            else:
                username = self._username_edit.text().strip()
                password = self._password_edit.text()
                container = self._locked.unlock(username, password)
        except core.CoveAuthError:
            self._register_failed_attempt()
            return
        except Exception as exc:  # noqa: BLE001 — граница UI
            QMessageBox.critical(self, "Cove", f"Не удалось открыть хранилище: {exc}")
            return
        self._on_unlocked(container, str(self._path))

    def _register_failed_attempt(self) -> None:
        attempt_limit = self._settings.get("login_attempt_limit", 0)
        self._failed_attempts += 1
        if attempt_limit and self._failed_attempts >= attempt_limit:
            self._status_label.setText(
                f"Превышен лимит попыток ({attempt_limit}). Перезапустите приложение."
            )
            self._login_buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(False)
            self._username_edit.setEnabled(False)
            self._password_edit.setEnabled(False)
            self._recovery_edit.setEnabled(False)
            self._use_recovery.setEnabled(False)
        else:
            remaining = (
                f" Осталось попыток: {attempt_limit - self._failed_attempts}."
                if attempt_limit
                else ""
            )
            self._status_label.setText(f"Неверный пароль или recovery-фраза.{remaining}")
