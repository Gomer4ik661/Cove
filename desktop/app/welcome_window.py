import os

from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import (
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

import cove_core_py as core

from . import config as config_module
from . import i18n
from .create_container_dialog import CreateContainerDialog
from .login_dialog import LoginDialog
from .recovery_phrase_dialog import RecoveryPhraseDialog


class WelcomeWindow(QMainWindow):
    """Если известно "основное" хранилище (`settings["default_container"]`),
    сразу после показа окна всплывает LoginDialog — вход "просто логин и
    пароль", без выбора файла каждый раз. Если пользователь отменит этот
    диалог (или основного хранилища ещё нет — первый запуск), под ним всё
    равно есть обычный экран "Создать"/"Открыть" — так что открыть другое
    хранилище или завести новое по-прежнему можно в любой момент."""

    def __init__(self, app, settings: dict, on_unlocked):
        super().__init__()
        self._app = app
        self._settings = settings
        self._on_unlocked = on_unlocked

        self.setWindowTitle(i18n.tr("Cove"))
        self.resize(480, 360)

        title = QLabel(i18n.tr("Cove"))
        title_font = title.font()
        title_font.setPointSize(28)
        title.setFont(title_font)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        subtitle = QLabel(i18n.tr("Зашифрованное хранилище файлов"))
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)

        create_btn = QPushButton(i18n.tr("Создать хранилище"))
        create_btn.clicked.connect(self._create_container)
        open_btn = QPushButton(i18n.tr("Открыть хранилище"))
        open_btn.clicked.connect(self._open_container)

        buttons_row = QHBoxLayout()
        buttons_row.addWidget(create_btn)
        buttons_row.addWidget(open_btn)

        self._recent_list = QListWidget()
        self._refresh_recent()
        self._recent_list.itemDoubleClicked.connect(self._open_recent)

        default_path = self._settings.get("default_container")
        self._default_label = QLabel()
        self._default_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._default_label.setWordWrap(True)
        forget_btn = QPushButton("Забыть основное хранилище")
        forget_btn.clicked.connect(self._forget_default)

        layout = QVBoxLayout()
        layout.addStretch()
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addSpacing(24)
        layout.addLayout(buttons_row)
        layout.addSpacing(12)
        if self._settings.get("remember_recent") and self._settings.get("recent_containers"):
            layout.addWidget(QLabel("Недавние:"))
            layout.addWidget(self._recent_list)
        if default_path:
            layout.addWidget(self._default_label)
            layout.addWidget(forget_btn)
        layout.addStretch()

        central = QWidget()
        central.setLayout(layout)
        self.setCentralWidget(central)

        if default_path and os.path.exists(default_path):
            self._default_label.setText(f"Основное хранилище: {default_path}")
            # Даём окну сначала отрисоваться, потом сразу открываем форму
            # входа — с точки зрения пользователя это и есть "спросили
            # логин/пароль", а не "надо было идти выбирать файл".
            QTimer.singleShot(0, lambda: self._unlock_path(default_path))
        elif default_path:
            # Файл сам исчез/переехал — не тащим экран входа в никуда,
            # просто честно забываем битую ссылку и показываем обычный выбор.
            config_module.clear_default_container(self._settings)

    def _forget_default(self) -> None:
        config_module.clear_default_container(self._settings)
        self._default_label.clear()

    def _refresh_recent(self) -> None:
        self._recent_list.clear()
        for path in self._settings.get("recent_containers", []):
            QListWidgetItem(path, self._recent_list)

    def _create_container(self) -> None:
        dialog = CreateContainerDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            container, recovery_phrase = core.Container.create(
                dialog.path(), dialog.username(), dialog.password()
            )
        except core.CoveAlreadyExistsError:
            QMessageBox.warning(self, "Cove", "Файл с таким путём уже существует.")
            return
        except Exception as exc:  # noqa: BLE001 — граница UI
            QMessageBox.critical(self, "Cove", f"Не удалось создать хранилище: {exc}")
            return

        RecoveryPhraseDialog(recovery_phrase, self).exec()

        config_module.remember_recent_container(self._settings, dialog.path())
        config_module.set_default_container(self._settings, dialog.path())
        self._on_unlocked(container, dialog.path())

    def _open_container(self) -> None:
        # DontUseNativeDialog — нативный диалог через xdg-desktop-portal на
        # некоторых системах открывается ненадёжно (пропадает/остаётся за
        # окном). Встроенный Qt-диалог от портала не зависит.
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Открыть хранилище",
            "",
            "Cove Storage (*.slr)",
            "",
            QFileDialog.Option.DontUseNativeDialog,
        )
        if not path:
            return
        self._unlock_path(path)

    def _open_recent(self, item: QListWidgetItem) -> None:
        self._unlock_path(item.text())

    def _unlock_path(self, path: str) -> None:
        try:
            locked = core.LockedContainer.open(path)
        except Exception as exc:  # noqa: BLE001 — граница UI
            QMessageBox.critical(self, "Cove", f"Не удалось открыть файл: {exc}")
            return

        login_dialog = LoginDialog(
            locked, self, attempt_limit=self._settings.get("login_attempt_limit", 0)
        )
        if login_dialog.exec() != QDialog.DialogCode.Accepted:
            return
        container = login_dialog.container()
        if container is None:
            return

        config_module.remember_recent_container(self._settings, path)
        config_module.set_default_container(self._settings, path)
        self._on_unlocked(container, path)
