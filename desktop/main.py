import sys

from PySide6.QtWidgets import QApplication

try:
    import cove_core_py  # noqa: F401 — только чтобы дать понятную ошибку при отсутствии сборки
except ImportError:
    print(
        "Не удалось импортировать cove_core_py. "
        "Соберите биндинги: ./scripts/build_python_bindings.sh",
        file=sys.stderr,
    )
    raise

from app import config as config_module
from app import i18n
from app.main_window import MainWindow
from app.theme import apply_theme
from app.welcome_window import WelcomeWindow


class AppController:
    def __init__(self, app: QApplication):
        self._app = app
        self._settings = config_module.load_settings()
        apply_theme(self._app, self._settings.get("theme", "light"))
        i18n.set_language(self._settings.get("language", "ru"))
        self._window = None
        self._show_welcome()

    def _show_welcome(self) -> None:
        self._window = WelcomeWindow(self._app, self._settings, self._on_unlocked)
        self._window.show()

    def _on_unlocked(self, container, container_path: str) -> None:
        self._window.close()
        self._window = MainWindow(
            container, self._app, self._settings, self._show_welcome, container_path=container_path
        )
        self._window.show()


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("Cove")
    app.setOrganizationName("Cove")

    controller = AppController(app)  # noqa: F841 — держим ссылку, иначе окна уйдут под GC

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
