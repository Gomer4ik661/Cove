import json
from pathlib import Path

from PySide6.QtCore import QStandardPaths

DEFAULT_SETTINGS = {
    "theme": "light",
    # 0 — отключена. Таймер бездействия в MainWindow (ROADMAP.md Фаза 12).
    "auto_lock_minutes": 15,
    # Порог неудачных попыток входа — считается в памяти самого диалога
    # входа (не в Core: см. THREAT_MODEL.md/ROADMAP.md Фаза 4 — DEK ещё не
    # получен на этот момент, шифровать счётчик в контейнере нечем).
    "login_attempt_limit": 5,
    "thumbnail_size": 160,
    "language": "ru",
    "autostart": False,
    # Порт для веб-доступа (Фаза 13) — только предпочтение порта, НЕ флаг
    # "запускать веб-сервер автоматически": сервер стартует лишь по явному
    # нажатию "Запустить" во вкладке "Веб" настроек, каждый раз заново.
    "web_port": 8443,
}


def _settings_path() -> Path:
    config_dir = Path(QStandardPaths.writableLocation(QStandardPaths.AppConfigLocation))
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir / "settings.json"


def default_container_path() -> Path:
    """Единственный путь к хранилищу — пользователь никогда его не
    выбирает, по образцу Android (storage/ContainerRegistry.kt:
    filesDir/containers/, без диалога выбора файла). Раньше путь был
    произвольным (поле "Файл хранилища (.slr)" + "Обзор…" в бывшем
    CreateContainerDialog) — по прямой просьбе пользователя это убрано
    в пользу входа сразу в форму логина (см. welcome_window.py)."""
    data_dir = Path(QStandardPaths.writableLocation(QStandardPaths.AppDataLocation))
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir / "cove.slr"


def load_settings() -> dict:
    path = _settings_path()
    if not path.exists():
        return dict(DEFAULT_SETTINGS)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return dict(DEFAULT_SETTINGS)
    return {**DEFAULT_SETTINGS, **data}


def save_settings(settings: dict) -> None:
    _settings_path().write_text(
        json.dumps(settings, ensure_ascii=False, indent=2), encoding="utf-8"
    )
