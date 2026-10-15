import socket
import webbrowser

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialogButtonBox,
    QDialog,
    QFormLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from . import autostart
from . import update_check

DEFAULT_WEB_PORT = 8443

# По прямой просьбе пользователя — удаление хранилища требует набрать это
# слово вручную (не просто "Да"/"Нет"), чтобы случайный клик не мог снести
# все данные без осознанного шага.
DELETE_CONFIRM_PHRASE = "УДАЛИТЬ"
# Код результата диалога, которым мы отличаем "подтверждено удаление" от
# обычных Accepted/Rejected — вызывающая сторона (MainWindow) не должна
# применять обычные настройки в этом случае.
DELETE_RESULT_CODE = 2

AUTO_LOCK_OPTIONS = [
    ("Никогда", 0),
    ("5 минут", 5),
    ("15 минут", 15),
    ("30 минут", 30),
]

THUMBNAIL_SIZE_OPTIONS = [
    ("Мелкие", 96),
    ("Средние", 160),
    ("Крупные", 224),
]

LANGUAGE_OPTIONS = [
    ("Русский", "ru"),
    ("English", "en"),
]


class _UpdateCheckWorker(QThread):
    """Сетевой запрос (GitHub API + скачивание манифеста) не должен висеть
    на UI-потоке — при зависшем DNS/медленной сети диалог настроек иначе
    замирал бы на весь _REQUEST_TIMEOUT_S (10с) без возможности даже
    нажать "Отмена". Не трогает Container — чисто сеть, поэтому обычные
    правила "PyO3-объект не для параллельных вызовов" (Фаза 8) тут ни при
    чём, отдельный поток безопасен."""

    finished_ok = Signal(object)  # update_check.UpdateResult
    finished_error = Signal(str)

    def run(self) -> None:
        try:
            result = update_check.check_for_updates()
        except update_check.UpdateCheckError as e:
            self.finished_error.emit(str(e))
        else:
            self.finished_ok.emit(result)


class SettingsDialog(QDialog):
    def __init__(self, settings: dict, parent=None, web_server=None, container_path: str | None = None):
        super().__init__(parent)
        self._settings = settings
        self._web_server = web_server
        self._container_path = container_path
        self.setWindowTitle("Настройки")
        self.setMinimumWidth(380)

        self._update_thread: _UpdateCheckWorker | None = None
        self._delete_confirmed = False

        tabs = QTabWidget()
        tabs.addTab(self._build_general_tab(settings), "Общие")
        tabs.addTab(self._build_security_tab(settings), "Безопасность")
        tabs.addTab(self._build_web_tab(settings), "Веб")
        tabs.addTab(self._build_updates_tab(), "Обновления")
        tabs.addTab(self._build_danger_tab(), "Хранилище")

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(tabs)
        layout.addWidget(buttons)

    def _build_general_tab(self, settings: dict) -> QWidget:
        self._theme_combo = QComboBox()
        self._theme_combo.addItem("Светлая", userData="light")
        self._theme_combo.addItem("Тёмная", userData="dark")
        self._theme_combo.setCurrentIndex(1 if settings.get("theme") == "dark" else 0)

        self._language_combo = QComboBox()
        for label, value in LANGUAGE_OPTIONS:
            self._language_combo.addItem(label, userData=value)
        current_lang = settings.get("language", "ru")
        idx = next((i for i, (_l, v) in enumerate(LANGUAGE_OPTIONS) if v == current_lang), 0)
        self._language_combo.setCurrentIndex(idx)

        self._thumbnail_combo = QComboBox()
        for label, value in THUMBNAIL_SIZE_OPTIONS:
            self._thumbnail_combo.addItem(label, userData=value)
        current_size = settings.get("thumbnail_size", 160)
        idx = next(
            (i for i, (_l, v) in enumerate(THUMBNAIL_SIZE_OPTIONS) if v == current_size), 1
        )
        self._thumbnail_combo.setCurrentIndex(idx)

        self._autostart_checkbox = QCheckBox("Запускать Cove при входе в систему")
        self._autostart_checkbox.setChecked(autostart.is_enabled())
        if not autostart.is_supported():
            self._autostart_checkbox.setEnabled(False)
            self._autostart_checkbox.setToolTip(
                "Реализовано только для Linux (XDG autostart). "
                "Для Windows/macOS появится вместе с настоящей упаковкой приложения (Фаза 16)."
            )

        form = QFormLayout()
        form.addRow("Тема:", self._theme_combo)
        form.addRow("Язык:", self._language_combo)
        note = QLabel(
            "Переключает только основной интерфейс (сайдбар, меню); "
            "полный перевод всех диалогов ещё не сделан."
        )
        note.setWordWrap(True)
        form.addRow("", note)
        form.addRow("Размер миниатюр:", self._thumbnail_combo)
        form.addRow("", self._autostart_checkbox)

        widget = QWidget()
        widget.setLayout(form)
        return widget

    def _build_security_tab(self, settings: dict) -> QWidget:
        self._auto_lock_combo = QComboBox()
        for label, minutes in AUTO_LOCK_OPTIONS:
            self._auto_lock_combo.addItem(label, userData=minutes)
        current_minutes = settings.get("auto_lock_minutes", 15)
        idx = next(
            (i for i, (_l, m) in enumerate(AUTO_LOCK_OPTIONS) if m == current_minutes), 2
        )
        self._auto_lock_combo.setCurrentIndex(idx)

        self._attempt_limit_spin = QSpinBox()
        self._attempt_limit_spin.setRange(0, 20)
        self._attempt_limit_spin.setSpecialValueText("Без лимита")
        self._attempt_limit_spin.setValue(settings.get("login_attempt_limit", 5))

        form = QFormLayout()
        form.addRow("Автоблокировка через:", self._auto_lock_combo)
        form.addRow("Лимит попыток входа:", self._attempt_limit_spin)

        widget = QWidget()
        widget.setLayout(form)
        return widget

    def _build_web_tab(self, settings: dict) -> QWidget:
        warning = QLabel(
            "Веб-доступ открывает это хранилище по HTTPS для устройств в вашей "
            "локальной сети (пока сервер запущен). Сертификат самоподписанный — "
            "браузер честно предупредит при первом заходе, это ожидаемо.\n\n"
            "Важно: не редактируйте одновременно через десктоп-приложение и "
            "через веб — файл хранилища пока не защищён межпроцессной "
            "блокировкой, и при одновременной записи более поздний commit "
            "молча перезапишет более ранний."
        )
        warning.setWordWrap(True)
        warning.setStyleSheet("color: #b5651d;")

        self._web_port_spin = QSpinBox()
        self._web_port_spin.setRange(1, 65535)
        self._web_port_spin.setValue(settings.get("web_port", DEFAULT_WEB_PORT))

        self._web_status_label = QLabel()
        self._web_toggle_btn = QPushButton()
        self._web_toggle_btn.clicked.connect(self._toggle_web_server)

        if self._web_server is None or self._container_path is None:
            self._web_port_spin.setEnabled(False)
            self._web_toggle_btn.setEnabled(False)
            self._web_status_label.setText("Недоступно в этом контексте.")
        else:
            self._refresh_web_status()

        form = QFormLayout()
        form.addRow(warning)
        form.addRow("Порт:", self._web_port_spin)
        form.addRow("Статус:", self._web_status_label)
        form.addRow("", self._web_toggle_btn)

        widget = QWidget()
        widget.setLayout(form)
        return widget

    def _refresh_web_status(self) -> None:
        running = self._web_server.is_running()
        self._web_port_spin.setEnabled(not running)
        if running:
            host = self._local_lan_address()
            port = self._web_server.port()
            self._web_status_label.setText(f"Запущен: https://{host}:{port}")
            self._web_toggle_btn.setText("Остановить")
        else:
            self._web_status_label.setText("Не запущен")
            self._web_toggle_btn.setText("Запустить")

    def _toggle_web_server(self) -> None:
        if self._web_server.is_running():
            self._web_server.stop()
        else:
            ok, error = self._web_server.start(self._container_path, self._web_port_spin.value())
            if not ok:
                self._web_status_label.setText(f"Ошибка: {error}")
                return
        self._refresh_web_status()

    def _build_updates_tab(self) -> QWidget:
        info = QLabel(
            f"Текущая версия: {update_check.CURRENT_VERSION}\n\n"
            "Проверка обновлений скачивает только небольшой подписанный "
            "манифест версии (не сам установочный файл) и проверяет его "
            "Ed25519-подпись — сама установка всегда остаётся ручной."
        )
        info.setWordWrap(True)

        self._update_status_label = QLabel("")
        self._update_status_label.setWordWrap(True)

        self._update_check_btn = QPushButton("Проверить обновления")
        self._update_check_btn.clicked.connect(self._start_update_check)

        self._update_open_btn = QPushButton("Открыть страницу релиза")
        self._update_open_btn.setVisible(False)
        self._update_open_btn.clicked.connect(self._open_release_page)
        self._pending_release_url: str | None = None

        form = QFormLayout()
        form.addRow(info)
        form.addRow("", self._update_check_btn)
        form.addRow("Статус:", self._update_status_label)
        form.addRow("", self._update_open_btn)

        widget = QWidget()
        widget.setLayout(form)
        return widget

    def _start_update_check(self) -> None:
        if self._update_thread is not None:
            return  # уже идёт проверка — не запускаем вторую поверх
        self._update_check_btn.setEnabled(False)
        self._update_open_btn.setVisible(False)
        self._update_status_label.setText("Проверка…")

        self._update_thread = _UpdateCheckWorker(self)
        self._update_thread.finished_ok.connect(self._on_update_check_ok)
        self._update_thread.finished_error.connect(self._on_update_check_error)
        self._update_thread.finished.connect(self._on_update_thread_finished)
        self._update_thread.start()

    def _on_update_check_ok(self, result) -> None:
        if result.update_available:
            self._update_status_label.setText(
                f"Доступна новая версия: {result.latest_version} "
                f"(у вас {update_check.CURRENT_VERSION})"
            )
            self._pending_release_url = result.release_url
            self._update_open_btn.setVisible(True)
        else:
            self._update_status_label.setText("У вас последняя версия.")

    def _on_update_check_error(self, message: str) -> None:
        self._update_status_label.setText(f"Не удалось проверить: {message}")

    def _on_update_thread_finished(self) -> None:
        self._update_check_btn.setEnabled(True)
        self._update_thread = None

    def _open_release_page(self) -> None:
        if self._pending_release_url:
            webbrowser.open(self._pending_release_url)

    def _build_danger_tab(self) -> QWidget:
        warning = QLabel(
            "Безвозвратно удаляет файл хранилища со всеми файлами, "
            "пользователями и журналом входов. Резервных копий приложение "
            "не хранит — отменить это действие невозможно."
        )
        warning.setWordWrap(True)
        warning.setStyleSheet("color: #b00020;")

        delete_btn = QPushButton("Удалить базу данных…")
        delete_btn.setStyleSheet("color: #b00020; font-weight: bold;")
        delete_btn.clicked.connect(self._confirm_delete_database)
        if self._container_path is None:
            delete_btn.setEnabled(False)

        form = QFormLayout()
        form.addRow(warning)
        form.addRow("", delete_btn)

        widget = QWidget()
        widget.setLayout(form)
        return widget

    def _confirm_delete_database(self) -> None:
        # Само удаление файла и возврат на экран приветствия — ответственность
        # MainWindow (у него, а не у этого диалога, есть открытый Container и
        # web-сервер, которые сначала нужно честно закрыть/остановить — см.
        # delete_confirmed()/DELETE_RESULT_CODE и main_window._delete_database()).
        dialog = QDialog(self)
        dialog.setWindowTitle("Удалить базу данных")
        layout = QVBoxLayout(dialog)

        text = QLabel(
            "Хранилище и все данные в нём "
            f"({self._container_path}) будут удалены навсегда.\n\n"
            f'Чтобы подтвердить, введите слово "{DELETE_CONFIRM_PHRASE}":'
        )
        text.setWordWrap(True)
        layout.addWidget(text)

        confirm_edit = QLineEdit()
        layout.addWidget(confirm_edit)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        ok_button = buttons.button(QDialogButtonBox.StandardButton.Ok)
        ok_button.setText("Удалить навсегда")
        ok_button.setEnabled(False)
        confirm_edit.textChanged.connect(
            lambda t: ok_button.setEnabled(t.strip() == DELETE_CONFIRM_PHRASE)
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        self._delete_confirmed = True
        self.done(DELETE_RESULT_CODE)

    def delete_confirmed(self) -> bool:
        return self._delete_confirmed

    def closeEvent(self, event) -> None:
        # QThread не должен быть уничтожен, пока ещё выполняется — иначе
        # Qt честно ругается в консоль ("QThread: Destroyed while thread
        # is still running") и в худшем случае это UB. Проверка сети
        # короткая (_REQUEST_TIMEOUT_S=10с в update_check.py), подождать
        # не страшно — это не блокировка основного окна приложения, только
        # закрытия уже открытого диалога настроек.
        if self._update_thread is not None:
            self._update_thread.quit()
            self._update_thread.wait()
        super().closeEvent(event)

    @staticmethod
    def _local_lan_address() -> str:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "<ip-этого-устройства>"

    def theme(self) -> str:
        return self._theme_combo.currentData()

    def language(self) -> str:
        return self._language_combo.currentData()

    def thumbnail_size(self) -> int:
        return self._thumbnail_combo.currentData()

    def autostart_enabled(self) -> bool:
        return self._autostart_checkbox.isChecked()

    def auto_lock_minutes(self) -> int:
        return self._auto_lock_combo.currentData()

    def login_attempt_limit(self) -> int:
        return self._attempt_limit_spin.value()

    def web_port(self) -> int:
        return self._web_port_spin.value()
