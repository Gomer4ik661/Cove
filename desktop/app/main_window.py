from dataclasses import dataclass, field

from PySide6.QtCore import QEvent, QSize, Qt, QTimer
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QStyle,
    QTabBar,
    QVBoxLayout,
    QWidget,
)

import cove_core_py as core

from . import autostart
from . import config as config_module
from . import file_kind
from . import i18n
from . import thumbnails
from .breadcrumb_bar import BreadcrumbBar
from .external_open import export_and_open_externally
from .viewer_dialog import open_viewer
from .add_user_dialog import AddUserDialog
from .change_password_dialog import ChangePasswordDialog
from .login_history_dialog import LoginHistoryDialog
from .manage_users_dialog import ManageUsersDialog
from .settings_dialog import SettingsDialog
from .theme import apply_theme
from .web_server import WebServerManager

ROOT_FOLDER_ID = 0
RECENT_LIMIT = 50

# (заголовок, тип раздела, доп. параметр): "root" — реальное дерево папок с
# навигацией, "trash" — корзина, "category" — виртуальный раздел по типу
# файла (доп. параметр — значение category для search()), "favorite" —
# избранное, "recent" — последние изменённые. Все "виртуальные" разделы —
# ROADMAP.md Фаза 10, построены поверх search() из Фазы 9 (никакого
# отдельного индекса под ними нет — та же resident File Table в памяти).
SECTIONS = [
    ("Библиотека", "root", None),
    ("Фото", "category", "image"),
    ("Видео", "category", "video"),
    ("Документы", "category", "document"),
    ("Музыка", "category", "audio"),
    ("Избранное", "favorite", None),
    ("Недавние", "recent", None),
    ("Корзина", "trash", None),
    ("Мои файлы", "root", None),
]

MAX_DISPLAY_NAME_LEN = 22

# События, которые считаются "активностью пользователя" для сброса таймера
# автоблокировки (ROADMAP.md Фаза 12) — перехватываются через event filter
# на уровне QApplication, чтобы ловить их независимо от того, какой именно
# дочерний виджет сейчас в фокусе.
_ACTIVITY_EVENT_TYPES = {
    QEvent.Type.MouseButtonPress,
    QEvent.Type.KeyPress,
    QEvent.Type.Wheel,
}


class _DropTargetMixin:
    """Общая реализация приёма drag&drop файлов из ОС — переопределённые
    методы Python-подкласса, а не атрибуты, подвешенные на голый экземпляр
    (в PySide6/Qt dragEnterEvent/dragMoveEvent/dropEvent диспетчеризуются
    через C++ vtable, и `widget.dropEvent = my_func` на объекте, который не
    является подклассом, эту диспетчеризацию не перехватывает).

    Нужен ОБОИМ виджетам содержимого — списку файлов и плейсхолдеру
    "здесь пока пусто": какой из них виден, зависит от того, есть ли уже
    файлы в разделе, а Qt адресует drag-событие тому виджету, что реально
    под курсором в этот момент, а не контейнеру-обёртке."""

    def _init_drop_target(self, on_files_dropped, can_accept_drop) -> None:
        self._on_files_dropped = on_files_dropped
        self._can_accept_drop = can_accept_drop
        self.setAcceptDrops(True)

    def dragEnterEvent(self, event) -> None:
        if event.mimeData().hasUrls() and self._can_accept_drop():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event) -> None:
        if event.mimeData().hasUrls() and self._can_accept_drop():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event) -> None:
        if not (event.mimeData().hasUrls() and self._can_accept_drop()):
            event.ignore()
            return
        paths = [url.toLocalFile() for url in event.mimeData().urls() if url.isLocalFile()]
        event.acceptProposedAction()
        self._on_files_dropped(paths)


class _DropListWidget(_DropTargetMixin, QListWidget):
    def __init__(self, on_files_dropped, can_accept_drop, parent=None):
        QListWidget.__init__(self, parent)
        self._init_drop_target(on_files_dropped, can_accept_drop)


class _DropLabel(_DropTargetMixin, QLabel):
    def __init__(self, on_files_dropped, can_accept_drop, parent=None):
        QLabel.__init__(self, parent)
        self._init_drop_target(on_files_dropped, can_accept_drop)


def _display_name(name: str) -> str:
    """Длинные имена обрезаются посередине с сохранением расширения —
    полное имя всегда доступно через tooltip. Без этого сетка миниатюр
    "разъезжается" под длину текста (setTextElideMode в IconMode не
    гарантирует перенос/обрезку одинаково на всех платформах)."""
    if len(name) <= MAX_DISPLAY_NAME_LEN:
        return name
    stem, dot, ext = name.rpartition(".")
    if dot and len(ext) <= 5:
        keep = MAX_DISPLAY_NAME_LEN - len(ext) - 4  # "…." + ext + запас
        return f"{stem[:max(keep, 1)]}….{ext}"
    return f"{name[:MAX_DISPLAY_NAME_LEN - 1]}…"


@dataclass
class _TabState:
    """Независимое состояние одной вкладки (ROADMAP.md Фаза 11) — раздел,
    путь по папкам и собственная история переходов. Виджеты содержимого
    (список/пустая подложка) при этом общие на все вкладки — при переключении
    просто перезаполняются под текущее состояние, а не дублируются."""

    section_row: int = 0
    folder_stack: list = field(default_factory=list)  # list[tuple[folder_id, name]]
    history: list = field(default_factory=list)  # list[tuple[section_row, tuple[folder_stack]]]
    history_pos: int = -1


class MainWindow(QMainWindow):
    """Главное окно — Фаза 5/6 (ROADMAP.md). Разделы «Библиотека»/«Мои файлы»
    и «Корзина» реальны (дёргают Core), остальные — честный empty state до
    Фазы 10 (виртуальные разделы по типу файла)."""

    def __init__(
        self,
        container: "core.Container",
        app,
        settings: dict,
        on_logout,
        container_path: str | None = None,
    ):
        super().__init__()
        self._container = container
        self._app = app
        self._settings = settings
        self._on_logout = on_logout
        self._container_path = container_path
        self._web_server = WebServerManager()
        self._section_kind = "root"
        self._section_extra = None
        self._folder_stack: list = []  # list[tuple[folder_id, name]], путь от корня
        self._tabs = [_TabState()]

        self.setWindowTitle("Cove")
        self.resize(1024, 640)

        self._sidebar = QListWidget()
        for title, _kind, _extra in SECTIONS:
            QListWidgetItem(i18n.tr(title), self._sidebar)
        self._settings_item = QListWidgetItem(i18n.tr("⚙ Настройки"), self._sidebar)
        self._sidebar.setCurrentRow(0)
        self._sidebar.setMaximumWidth(200)
        self._sidebar.currentItemChanged.connect(self._on_section_changed)

        self._tab_bar = QTabBar()
        self._tab_bar.setTabsClosable(True)
        self._tab_bar.setExpanding(False)
        self._tab_bar.addTab(self._tab_label(i18n.tr("Библиотека"), []))
        self._tab_bar.currentChanged.connect(self._on_tab_changed)
        self._tab_bar.tabCloseRequested.connect(self._on_tab_close_requested)

        self._new_tab_button = QPushButton("+")
        self._new_tab_button.setToolTip("Новая вкладка")
        self._new_tab_button.setFixedWidth(28)
        # Глобальный QSS даёт кнопкам padding 6px 14px — на ширине 28px это
        # съедает всё место под символ "+", и кнопка выглядит пустой.
        self._new_tab_button.setStyleSheet("padding: 2px;")
        self._new_tab_button.clicked.connect(self._add_tab)

        tab_row = QHBoxLayout()
        tab_row.addWidget(self._tab_bar, stretch=1)
        tab_row.addWidget(self._new_tab_button)

        # Иконки со стандартной темы стиля, а не юникод-глифы (◀▶⟳) — на
        # части систем в используемом шрифте таких символов нет, и кнопка
        # рисуется нечитаемым "квадратиком"/случайным знаком.
        self._back_button = QPushButton()
        self._back_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_ArrowBack))
        self._back_button.setToolTip("Назад")
        self._back_button.setFixedWidth(32)
        self._back_button.setStyleSheet("padding: 2px;")
        self._back_button.clicked.connect(self._go_back)
        self._back_button.setEnabled(False)

        self._forward_button = QPushButton()
        self._forward_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_ArrowForward))
        self._forward_button.setToolTip("Вперёд")
        self._forward_button.setFixedWidth(32)
        self._forward_button.setStyleSheet("padding: 2px;")
        self._forward_button.clicked.connect(self._go_forward)
        self._forward_button.setEnabled(False)

        self._up_button = QPushButton("⬆ Вверх")
        self._up_button.clicked.connect(self._navigate_up)
        self._up_button.setEnabled(False)

        self._refresh_button = QPushButton()
        self._refresh_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_BrowserReload))
        self._refresh_button.setToolTip("Обновить")
        self._refresh_button.setFixedWidth(32)
        self._refresh_button.setStyleSheet("padding: 2px;")
        self._refresh_button.clicked.connect(self._refresh_content)

        self._breadcrumb_bar = BreadcrumbBar(on_segment_clicked=self._on_breadcrumb_clicked)

        self._search_edit = QLineEdit()
        self._search_edit.setPlaceholderText("Поиск по имени…")
        self._search_edit.setClearButtonEnabled(True)
        self._search_edit.setMaximumWidth(240)
        self._search_edit.textChanged.connect(self._refresh_content)

        path_bar = QHBoxLayout()
        path_bar.addWidget(self._back_button)
        path_bar.addWidget(self._forward_button)
        path_bar.addWidget(self._up_button)
        path_bar.addWidget(self._refresh_button)
        path_bar.addWidget(self._breadcrumb_bar, stretch=1)
        path_bar.addWidget(self._search_edit)

        self._content_list = _DropListWidget(
            on_files_dropped=self._handle_dropped_files,
            can_accept_drop=lambda: self._section_kind in ("root", "category"),
        )
        self._content_list.setViewMode(QListWidget.ViewMode.IconMode)
        self._content_list.setUniformItemSizes(True)
        self._content_list.setResizeMode(QListWidget.ResizeMode.Adjust)
        self._content_list.setMovement(QListWidget.Movement.Static)
        self._content_list.setWordWrap(False)
        self._content_list.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        self._content_list.setSpacing(12)
        self._content_list.itemDoubleClicked.connect(self._on_item_activated)
        self._content_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._content_list.customContextMenuRequested.connect(self._show_context_menu)
        self._content_list.setDragDropMode(QListWidget.DragDropMode.DropOnly)
        self._apply_thumbnail_size()

        self._empty_label = _DropLabel(
            on_files_dropped=self._handle_dropped_files,
            can_accept_drop=lambda: self._section_kind in ("root", "category"),
        )
        self._empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._content_stack = QStackedWidget()
        self._content_stack.addWidget(self._empty_label)
        self._content_stack.addWidget(self._content_list)

        content_column = QVBoxLayout()
        content_column.addLayout(tab_row)
        content_column.addLayout(path_bar)
        content_column.addWidget(self._content_stack, stretch=1)
        content_widget = QWidget()
        content_widget.setLayout(content_column)

        central = QWidget()
        layout = QHBoxLayout(central)
        layout.addWidget(self._sidebar)
        layout.addWidget(content_widget, stretch=1)
        self.setCentralWidget(central)

        self._build_menu()
        self._navigate_to(0, [], record=True)
        self._update_status_bar()

        self._auto_lock_timer = QTimer(self)
        self._auto_lock_timer.setSingleShot(True)
        self._auto_lock_timer.timeout.connect(self._on_auto_lock_timeout)
        self._apply_auto_lock_setting()
        QApplication.instance().installEventFilter(self)

    # ---- меню и статус-бар -------------------------------------------------

    def _build_menu(self) -> None:
        menu_bar = self.menuBar()

        file_menu = menu_bar.addMenu(i18n.tr("Файл"))
        self._import_action = QAction("Импортировать файл…", self)
        self._import_action.triggered.connect(self._import_files_dialog)
        file_menu.addAction(self._import_action)
        self._new_folder_action = QAction("Новая папка…", self)
        self._new_folder_action.triggered.connect(self._new_folder_dialog)
        file_menu.addAction(self._new_folder_action)

        user_menu = menu_bar.addMenu(i18n.tr("Пользователи"))
        self._add_user_action = QAction("Добавить пользователя…", self)
        self._add_user_action.triggered.connect(self._add_user)
        self._add_user_action.setEnabled(self._container.current_role() == "admin")
        user_menu.addAction(self._add_user_action)

        self._manage_users_action = QAction("Управление пользователями…", self)
        self._manage_users_action.triggered.connect(self._manage_users)
        self._manage_users_action.setEnabled(self._container.current_role() == "admin")
        user_menu.addAction(self._manage_users_action)

        change_pw_action = QAction("Сменить пароль…", self)
        change_pw_action.triggered.connect(self._change_password)
        user_menu.addAction(change_pw_action)

        login_history_action = QAction("Журнал входов…", self)
        login_history_action.triggered.connect(self._show_login_history)
        user_menu.addAction(login_history_action)

        session_menu = menu_bar.addMenu(i18n.tr("Сессия"))
        logout_action = QAction("Выйти", self)
        logout_action.triggered.connect(self._logout)
        session_menu.addAction(logout_action)

    def _update_status_bar(self) -> None:
        username = self._container.current_username()
        role = self._container.current_role()
        self.statusBar().showMessage(f"Вошли как {username} ({role})")

    # ---- вкладки --------------------------------------------------------------

    def _current_tab(self) -> _TabState:
        return self._tabs[self._tab_bar.currentIndex()]

    def _tab_label(self, section_title: str, folder_stack: list) -> str:
        label = folder_stack[-1][1] if folder_stack else section_title
        return label if len(label) <= 18 else f"{label[:17]}…"

    def _add_tab(self) -> None:
        self._tabs.append(_TabState())
        self._tab_bar.addTab(self._tab_label(i18n.tr("Библиотека"), []))
        self._tab_bar.setCurrentIndex(self._tab_bar.count() - 1)  # -> _on_tab_changed

    def _on_tab_changed(self, index: int) -> None:
        if index < 0 or index >= len(self._tabs):
            return
        tab = self._tabs[index]
        # record=True здесь безопасно и для уже видевшей навигацию вкладки
        # (запись продублирует текущую позицию в её же истории — _record_history
        # это распознаёт и не добавляет дубликат), и для только что созданной
        # пустой вкладки (для которой это будет первая, стартовая запись).
        self._navigate_to(tab.section_row, tab.folder_stack)

    def _on_tab_close_requested(self, index: int) -> None:
        if len(self._tabs) <= 1:
            return  # всегда должна остаться хотя бы одна вкладка
        del self._tabs[index]
        self._tab_bar.removeTab(index)  # сама переключит currentIndex при необходимости

    # ---- навигация по разделам/папкам/истории ----------------------------------

    def _current_folder_id(self) -> int:
        return self._folder_stack[-1][0] if self._folder_stack else ROOT_FOLDER_ID

    def _navigate_to(self, section_row: int, folder_stack: list, *, record: bool = True) -> None:
        title_ru, kind, extra = SECTIONS[section_row]
        title = i18n.tr(title_ru)

        self._sidebar.blockSignals(True)
        self._sidebar.setCurrentRow(section_row)
        self._sidebar.blockSignals(False)

        self._section_kind = kind
        self._section_extra = extra
        self._folder_stack = list(folder_stack)

        tab = self._current_tab()
        tab.section_row = section_row
        tab.folder_stack = list(folder_stack)
        self._tab_bar.setTabText(self._tab_bar.currentIndex(), self._tab_label(title, folder_stack))

        self._search_edit.blockSignals(True)
        self._search_edit.clear()
        self._search_edit.blockSignals(False)

        if record:
            self._record_history()
        self._update_nav_buttons()
        self._refresh_breadcrumbs(title)
        self._refresh_content()

    def _refresh_breadcrumbs(self, title: str) -> None:
        segments = [(title, [])]
        accumulated: list = []
        for folder_id, folder_name in self._folder_stack:
            accumulated = accumulated + [(folder_id, folder_name)]
            segments.append((folder_name, accumulated))
        self._breadcrumb_bar.set_path(segments)

    def _on_breadcrumb_clicked(self, folder_stack: list) -> None:
        self._navigate_to(self._sidebar.currentRow(), folder_stack)

    def _record_history(self) -> None:
        tab = self._current_tab()
        entry = (tab.section_row, tuple(tab.folder_stack))
        tab.history = tab.history[: tab.history_pos + 1]  # отбросить "будущее" при новом переходе
        if not tab.history or tab.history[-1] != entry:
            tab.history.append(entry)
            tab.history_pos = len(tab.history) - 1

    def _update_nav_buttons(self) -> None:
        tab = self._current_tab()
        self._back_button.setEnabled(tab.history_pos > 0)
        self._forward_button.setEnabled(tab.history_pos < len(tab.history) - 1)
        self._up_button.setEnabled(
            self._section_kind in ("root", "category") and bool(self._folder_stack)
        )

    def _go_back(self) -> None:
        tab = self._current_tab()
        if tab.history_pos <= 0:
            return
        tab.history_pos -= 1
        row, stack = tab.history[tab.history_pos]
        self._navigate_to(row, list(stack), record=False)

    def _go_forward(self) -> None:
        tab = self._current_tab()
        if tab.history_pos >= len(tab.history) - 1:
            return
        tab.history_pos += 1
        row, stack = tab.history[tab.history_pos]
        self._navigate_to(row, list(stack), record=False)

    def _on_section_changed(self, current: QListWidgetItem, _previous) -> None:
        if current is self._settings_item:
            self._open_settings()
            self._sidebar.blockSignals(True)
            self._sidebar.setCurrentRow(self._current_tab().section_row)
            self._sidebar.blockSignals(False)
            return
        index = self._sidebar.row(current)
        self._navigate_to(index, [])

    def _navigate_into(self, folder_id: int, folder_name: str) -> None:
        self._navigate_to(self._sidebar.currentRow(), self._folder_stack + [(folder_id, folder_name)])

    def _navigate_up(self) -> None:
        if not self._folder_stack:
            return
        self._navigate_to(self._sidebar.currentRow(), self._folder_stack[:-1])

    def _on_item_activated(self, item: QListWidgetItem) -> None:
        if self._section_kind == "trash":
            return
        entry = item.data(Qt.ItemDataRole.UserRole)
        if entry is None:
            return
        if entry.is_folder:
            # Папки существуют в реальном дереве — root и category (теперь
            # тоже навигация по папкам, только с фильтром по типу файла).
            # В favorite/recent список плоский, навигация туда не ведёт.
            if self._section_kind in ("root", "category"):
                self._navigate_into(entry.file_id, entry.name)
        else:
            open_viewer(self._container, entry, self)

    # ---- отрисовка содержимого ----------------------------------------------

    def _apply_thumbnail_size(self) -> None:
        # Настройка "размер миниатюр" — это только размер ОТОБРАЖЕНИЯ иконки
        # в сетке, а не разрешение, в котором генерируется и кэшируется сама
        # миниатюра внутри контейнера (Фаза 8 хранит фиксированное разрешение
        # thumbnails.THUMBNAIL_SIZE) — Qt сам растягивает/сжимает картинку
        # под нужный размер иконки, перегенерировать кэш не нужно.
        size = self._settings.get("thumbnail_size", thumbnails.THUMBNAIL_SIZE)
        self._content_list.setIconSize(QSize(size, size))
        self._content_list.setGridSize(QSize(size + 24, size + 48))

    def _icon_for_entry(self, entry) -> QIcon:
        """Для картинок — реальная миниатюра (из кэша в контейнере или
        сгенерированная на месте, ROADMAP.md Фаза 8), иначе — системная
        иконка. Генерация синхронная и по одному элементу за раз — честно
        задокументированное упрощение вместо фонового пула потоков (см.
        ROADMAP.md): так надёжнее, учитывая что PyO3-объект `Container`
        не рассчитан на параллельные вызовы из нескольких потоков сразу."""
        if entry.is_folder:
            return self.style().standardIcon(QStyle.StandardPixmap.SP_DirIcon)

        if file_kind.kind_of(entry.name) == "image":
            thumb_id = self._container.find_thumbnail(entry.file_id)
            if thumb_id is None:
                try:
                    read_len = min(entry.size, 20 * 1024 * 1024)  # не тащим в память гигантские файлы
                    source_bytes = bytes(self._container.read_at(entry.file_id, 0, read_len))
                    png_bytes = thumbnails.generate_thumbnail_bytes(source_bytes)
                except Exception:  # noqa: BLE001 — превью best-effort, не должно ронять список
                    png_bytes = None
                if png_bytes is not None:
                    try:
                        thumb_id = self._container.thumbnail(entry.file_id, png_bytes)
                    except Exception:  # noqa: BLE001
                        thumb_id = None
            if thumb_id is not None:
                try:
                    thumb_size = self._container.file_size(thumb_id)
                    thumb_bytes = bytes(self._container.read_at(thumb_id, 0, thumb_size))
                    pixmap = thumbnails.pixmap_from_bytes(thumb_bytes)
                    if not pixmap.isNull():
                        return QIcon(pixmap)
                except Exception:  # noqa: BLE001
                    pass

        return self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon)

    def _refresh_content(self) -> None:
        # Кнопки навигации (Назад/Вперёд/Вверх) обновляются в _update_nav_buttons(),
        # вызываемой из _navigate_to() — здесь трогаем только то, что зависит
        # от содержимого текущего раздела, а не от факта перехода.
        self._search_edit.setEnabled(self._section_kind != "trash")

        search_text = self._search_edit.text().strip() if self._section_kind != "trash" else ""

        try:
            if self._section_kind == "trash":
                entries = self._container.list_trash()
            elif self._section_kind == "root" and not search_text:
                entries = self._container.list_dir(self._current_folder_id())
            elif self._section_kind == "root":
                # Поиск — обход resident File Table в памяти (ROADMAP.md
                # Фаза 9), рекурсивно внутри текущей папки.
                entries = self._container.search(
                    name_contains=search_text or None, folder_id=self._current_folder_id()
                )
            elif self._section_kind == "category" and not search_text:
                # Раньше был плоский search(category=...) без привязки к
                # папке — новая папка, созданная во вкладке "Фото", в неё не
                # попадала (только в "Библиотеку"). Теперь та же навигация по
                # папкам, что и в root, только с фильтром файлов по категории
                # на клиенте — папки показываются всегда, независимо от того,
                # что внутри (жалоба пользователя: "при создании папки в
                # вкладке фото оно не отображается в фото").
                entries = self._container.list_dir(self._current_folder_id())
                entries = [
                    e for e in entries
                    if e.is_folder or file_kind.category_of(e.name) == self._section_extra
                ]
            elif self._section_kind == "category":
                entries = self._container.search(
                    name_contains=search_text or None,
                    folder_id=self._current_folder_id(),
                    category=self._section_extra,
                )
            elif self._section_kind == "favorite":
                entries = self._container.search(name_contains=search_text or None, favorite=True)
            else:  # "recent"
                entries = self._container.search(name_contains=search_text or None)
                entries = sorted(entries, key=lambda e: e.modified_at, reverse=True)[:RECENT_LIMIT]
        except Exception as exc:  # noqa: BLE001 — граница UI
            QMessageBox.critical(self, "Cove", f"Не удалось получить содержимое: {exc}")
            entries = []

        self._import_action.setEnabled(self._section_kind in ("root", "category"))
        self._new_folder_action.setEnabled(self._section_kind in ("root", "category"))

        self._content_list.clear()
        for entry in entries:
            item = QListWidgetItem(_display_name(entry.name), self._content_list)
            item.setData(Qt.ItemDataRole.UserRole, entry)
            item.setIcon(self._icon_for_entry(entry))
            item.setToolTip(entry.name)
            item.setTextAlignment(Qt.AlignmentFlag.AlignHCenter)

        if entries:
            self._content_stack.setCurrentWidget(self._content_list)
        else:
            if self._section_kind == "trash":
                empty_text = "В корзине пусто."
            elif search_text:
                empty_text = f"По запросу «{search_text}» ничего не найдено."
            elif self._section_kind == "favorite":
                empty_text = "Пока нет избранных файлов.\nОтметьте файл через контекстное меню."
            elif self._section_kind == "category":
                empty_text = "Файлов такого типа пока нет."
            elif self._section_kind == "recent":
                empty_text = "Пока нет недавних изменений."
            else:
                empty_text = "Здесь пока пусто.\nПеретащите файлы сюда или используйте меню «Файл»."
            self._empty_label.setText(empty_text)
            self._content_stack.setCurrentWidget(self._empty_label)

    # ---- drag & drop импорт --------------------------------------------------

    def _handle_dropped_files(self, paths: list[str]) -> None:
        for path in paths:
            self._import_path(path)

    # ---- операции с файлами ---------------------------------------------------

    def _import_path(self, path: str) -> None:
        try:
            self._container.import_file(path, self._current_folder_id())
        except Exception as exc:  # noqa: BLE001 — граница UI
            QMessageBox.critical(self, "Cove", f"Не удалось импортировать «{path}»: {exc}")
        else:
            self._refresh_content()

    def _import_files_dialog(self) -> None:
        # DontUseNativeDialog — на некоторых системах нативный диалог идёт
        # через xdg-desktop-portal и иногда открывается за окном/вообще не
        # появляется (та же природа, что и проблема с drag&drop). Встроенный
        # Qt-диалог не зависит от портала и работает всегда одинаково.
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Импортировать файлы", "", "", "", QFileDialog.Option.DontUseNativeDialog
        )
        for path in paths:
            self._import_path(path)

    def _new_folder_dialog(self) -> None:
        name, ok = QInputDialog.getText(self, "Новая папка", "Название папки:")
        if not ok or not name.strip():
            return
        try:
            self._container.create_folder(name.strip(), self._current_folder_id())
        except Exception as exc:  # noqa: BLE001 — граница UI
            QMessageBox.critical(self, "Cove", f"Не удалось создать папку: {exc}")
        else:
            self._refresh_content()

    def _selected_entry(self):
        item = self._content_list.currentItem()
        if item is None:
            return None
        return item.data(Qt.ItemDataRole.UserRole)

    def _show_context_menu(self, pos) -> None:
        menu = QMenu(self)

        if self._section_kind in ("root", "category"):
            menu.addAction("Импортировать файл…", self._import_files_dialog)
            menu.addAction("Новая папка…", self._new_folder_dialog)

        entry = self._selected_entry()
        if entry is not None:
            menu.addSeparator()
            if self._section_kind == "trash":
                menu.addAction("Восстановить", lambda: self._restore_entry(entry))
                menu.addAction("Удалить навсегда", lambda: self._delete_entry(entry, permanent=True))
            else:
                if entry.is_folder and self._section_kind in ("root", "category"):
                    menu.addAction("Открыть", lambda: self._navigate_into(entry.file_id, entry.name))
                elif not entry.is_folder:
                    menu.addAction("Просмотреть", lambda: open_viewer(self._container, entry, self))
                    menu.addAction("Экспортировать…", lambda: self._export_entry(entry))
                    menu.addAction(
                        "Открыть во внешнем приложении…", lambda: self._open_externally(entry)
                    )
                favorite_label = "Убрать из избранного" if entry.favorite else "Добавить в избранное"
                menu.addAction(favorite_label, lambda: self._toggle_favorite(entry))
                menu.addAction("Переименовать…", lambda: self._rename_entry(entry))
                menu.addAction("Удалить", lambda: self._delete_entry(entry, permanent=False))

        if not menu.isEmpty():
            menu.exec(self._content_list.viewport().mapToGlobal(pos))

    def _rename_entry(self, entry) -> None:
        name, ok = QInputDialog.getText(self, "Переименовать", "Новое имя:", text=entry.name)
        if not ok or not name.strip():
            return
        try:
            self._container.rename_file(entry.file_id, name.strip())
        except Exception as exc:  # noqa: BLE001 — граница UI
            QMessageBox.critical(self, "Cove", f"Не удалось переименовать: {exc}")
        else:
            self._refresh_content()

    def _delete_entry(self, entry, *, permanent: bool) -> None:
        question = (
            f"Удалить «{entry.name}» навсегда? Это необратимо."
            if permanent
            else f"Переместить «{entry.name}» в корзину?"
        )
        if QMessageBox.question(self, "Cove", question) != QMessageBox.StandardButton.Yes:
            return
        try:
            self._container.delete_file(entry.file_id)
            if permanent:
                # delete_file на уже находящейся в корзине записи = окончательное удаление.
                pass
        except Exception as exc:  # noqa: BLE001 — граница UI
            QMessageBox.critical(self, "Cove", f"Не удалось удалить: {exc}")
        else:
            self._refresh_content()

    def _toggle_favorite(self, entry) -> None:
        try:
            self._container.set_favorite(entry.file_id, not entry.favorite)
        except Exception as exc:  # noqa: BLE001 — граница UI
            QMessageBox.critical(self, "Cove", f"Не удалось изменить избранное: {exc}")
        else:
            self._refresh_content()

    def _restore_entry(self, entry) -> None:
        try:
            self._container.restore_file(entry.file_id)
        except Exception as exc:  # noqa: BLE001 — граница UI
            QMessageBox.critical(self, "Cove", f"Не удалось восстановить: {exc}")
        else:
            self._refresh_content()

    def _export_entry(self, entry) -> None:
        dest, _ = QFileDialog.getSaveFileName(
            self, "Экспортировать", entry.name, "", "", QFileDialog.Option.DontUseNativeDialog
        )
        if not dest:
            return
        try:
            self._container.export_file(entry.file_id, dest)
        except Exception as exc:  # noqa: BLE001 — граница UI
            QMessageBox.critical(self, "Cove", f"Не удалось экспортировать: {exc}")
        else:
            QMessageBox.information(self, "Cove", "Файл экспортирован.")

    def _open_externally(self, entry) -> None:
        try:
            tmp_path = export_and_open_externally(self._container, entry)
        except Exception as exc:  # noqa: BLE001 — граница UI
            QMessageBox.critical(self, "Cove", f"Не удалось открыть файл: {exc}")
            return

        answer = QMessageBox.question(
            self,
            "Cove",
            f"Файл «{entry.name}» открыт во внешнем приложении.\n"
            "Когда закончите редактировать и сохраните файл там — нажмите "
            "«Да», чтобы записать изменения обратно в хранилище.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if answer == QMessageBox.StandardButton.Yes:
            try:
                self._container.replace_file_content(entry.file_id, str(tmp_path))
            except Exception as exc:  # noqa: BLE001 — граница UI
                QMessageBox.critical(self, "Cove", f"Не удалось сохранить изменения: {exc}")
            else:
                self._refresh_content()

    # ---- пользователи/настройки/сессия ----------------------------------------

    def _add_user(self) -> None:
        dialog = AddUserDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            self._container.add_user(dialog.username(), dialog.password(), dialog.role())
        except core.CoveAlreadyExistsError:
            QMessageBox.warning(self, "Cove", "Пользователь с таким именем уже существует.")
        except core.CovePermissionError:
            QMessageBox.warning(self, "Cove", "Недостаточно прав.")
        except Exception as exc:  # noqa: BLE001 — граница UI
            QMessageBox.critical(self, "Cove", f"Не удалось добавить пользователя: {exc}")
        else:
            QMessageBox.information(self, "Cove", "Пользователь добавлен.")

    def _manage_users(self) -> None:
        ManageUsersDialog(self._container, self).exec()

    def _show_login_history(self) -> None:
        LoginHistoryDialog(self._container, self).exec()

    def _change_password(self) -> None:
        username = self._container.current_username()
        dialog = ChangePasswordDialog(username, self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            self._container.change_password(username, dialog.old_password(), dialog.new_password())
        except core.CoveAuthError:
            QMessageBox.warning(self, "Cove", "Текущий пароль указан неверно.")
        except Exception as exc:  # noqa: BLE001 — граница UI
            QMessageBox.critical(self, "Cove", f"Не удалось сменить пароль: {exc}")
        else:
            QMessageBox.information(self, "Cove", "Пароль изменён.")

    def _open_settings(self) -> None:
        dialog = SettingsDialog(
            self._settings,
            self,
            web_server=self._web_server,
            container_path=self._container_path,
        )
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        self._settings["theme"] = dialog.theme()
        self._settings["remember_recent"] = dialog.remember_recent()
        self._settings["thumbnail_size"] = dialog.thumbnail_size()
        self._settings["auto_lock_minutes"] = dialog.auto_lock_minutes()
        self._settings["login_attempt_limit"] = dialog.login_attempt_limit()
        self._settings["web_port"] = dialog.web_port()

        language_changed = dialog.language() != self._settings.get("language", "ru")
        self._settings["language"] = dialog.language()
        i18n.set_language(dialog.language())  # применится к следующему окну (Welcome/MainWindow)

        if autostart.is_supported():
            autostart.set_enabled(dialog.autostart_enabled())

        config_module.save_settings(self._settings)
        apply_theme(self._app, self._settings["theme"])
        self._apply_thumbnail_size()
        self._refresh_content()
        self._apply_auto_lock_setting()

        if language_changed:
            QMessageBox.information(
                self,
                "Cove",
                "Язык интерфейса изменится при следующем входе в хранилище.",
            )

    def _logout(self) -> None:
        self._teardown_auto_lock()
        self._web_server.stop()
        self._close_container_quietly()
        self.close()
        self._on_logout()

    def _close_container_quietly(self) -> None:
        try:
            self._container.close()
        except Exception as exc:  # noqa: BLE001 — граница UI, не давать закрытию упасть молча
            QMessageBox.critical(self, "Cove", f"Ошибка при закрытии хранилища: {exc}")

    def closeEvent(self, event) -> None:
        # container.close() идемпотентен — если _logout() уже закрыл, это no-op.
        # web_server.stop() тоже идемпотентен (no-op, если уже остановлен).
        self._teardown_auto_lock()
        self._web_server.stop()
        self._close_container_quietly()
        super().closeEvent(event)

    # ---- автоблокировка --------------------------------------------------------

    def _apply_auto_lock_setting(self) -> None:
        minutes = self._settings.get("auto_lock_minutes", 0)
        if minutes and minutes > 0:
            self._auto_lock_timer.start(int(minutes * 60 * 1000))
        else:
            self._auto_lock_timer.stop()

    def eventFilter(self, watched, event) -> bool:  # noqa: N802 — переопределение метода Qt
        if event.type() in _ACTIVITY_EVENT_TYPES and self._auto_lock_timer.isActive():
            self._apply_auto_lock_setting()  # активность — просто перезапускаем отсчёт
        return super().eventFilter(watched, event)

    def _on_auto_lock_timeout(self) -> None:
        self._logout()

    def _teardown_auto_lock(self) -> None:
        app = QApplication.instance()
        if app is not None:
            app.removeEventFilter(self)
        self._auto_lock_timer.stop()
