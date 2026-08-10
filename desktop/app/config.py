import json
from pathlib import Path

from PySide6.QtCore import QStandardPaths

DEFAULT_SETTINGS = {
    "theme": "light",
    "remember_recent": False,
    "recent_containers": [],
    # Путь к "основному" хранилищу — в отличие от recent_containers,
    # запоминается ВСЕГДА, не по галочке remember_recent. Осознанная смена
    # поведения по просьбе пользователя: вход должен сразу спрашивать
    # логин/пароль, а не открывать диалог выбора файла каждый раз. Раньше
    # путь к хранилищу был опциональным именно из соображений приватности
    # (FORMAT.md: путь может выдавать факт существования тайника) — здесь
    # этот компромисс сознательно принят ради удобства.
    "default_container": None,
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
MAX_RECENT = 5


def _settings_path() -> Path:
    config_dir = Path(QStandardPaths.writableLocation(QStandardPaths.AppConfigLocation))
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir / "settings.json"


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


def remember_recent_container(settings: dict, path: str) -> None:
    if not settings.get("remember_recent"):
        return
    recent = [p for p in settings.get("recent_containers", []) if p != path]
    recent.insert(0, path)
    settings["recent_containers"] = recent[:MAX_RECENT]
    save_settings(settings)


def clear_recent_containers(settings: dict) -> None:
    settings["recent_containers"] = []
    save_settings(settings)


def set_default_container(settings: dict, path: str) -> None:
    settings["default_container"] = path
    save_settings(settings)


def clear_default_container(settings: dict) -> None:
    settings["default_container"] = None
    save_settings(settings)
