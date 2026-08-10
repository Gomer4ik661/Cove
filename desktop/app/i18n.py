"""Минимальный i18n — ROADMAP.md Фаза 12. Осознанно НЕ полноценная
локализация всего приложения (это отдельный объём работы — извлечь и
перевести все ~100+ строк по всем диалогам), а честно ограниченный набор:
самый заметный "хром" — сайдбар, меню, стартовый экран. Всё остальное
остаётся на русском независимо от выбранного языка; это явно
задокументировано в ROADMAP.md, а не выдаётся за полный перевод.

Строка-ключ — сам русский текст (принятая практика при небольшом наборе
переводов), отсутствующий перевод — просто возвращает оригинал."""

TRANSLATIONS = {
    "en": {
        "Cove": "Cove",
        "Зашифрованное хранилище файлов": "Encrypted file storage",
        "Создать хранилище": "Create storage",
        "Открыть хранилище": "Open storage",
        "Библиотека": "Library",
        "Фото": "Photos",
        "Видео": "Video",
        "Документы": "Documents",
        "Музыка": "Music",
        "Избранное": "Favorites",
        "Недавние": "Recent",
        "Корзина": "Trash",
        "Мои файлы": "My Files",
        "⚙ Настройки": "⚙ Settings",
        "Файл": "File",
        "Пользователи": "Users",
        "Сессия": "Session",
    }
}

_current_language = "ru"


def set_language(language: str) -> None:
    global _current_language
    _current_language = language if language in TRANSLATIONS else "ru"


def current_language() -> str:
    return _current_language


def tr(text: str) -> str:
    return TRANSLATIONS.get(_current_language, {}).get(text, text)
