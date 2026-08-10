from pathlib import Path

IMAGE_EXT = {"png", "jpg", "jpeg", "gif", "webp", "avif", "heif", "heic", "bmp", "tif", "tiff"}
VIDEO_EXT = {"mp4", "mkv", "avi", "mov", "webm"}
AUDIO_EXT = {"mp3", "flac", "aac", "ogg"}
TEXT_EXT = {"txt"}
MARKDOWN_EXT = {"md"}
PDF_EXT = {"pdf"}
RAW_EXT = {"cr2", "nef", "arw", "raw", "dng", "orf", "rw2"}


def extension_of(name: str) -> str:
    return Path(name).suffix.lower().lstrip(".")


def category_of(name: str) -> str:
    """Категория для вкладок Фото/Видео/Документы/Музыка (SECTIONS в
    main_window.py) — та же классификация, что и Core::categorize()
    (core/src/container/mod.rs), используется для клиентской фильтрации
    list_dir() при построении навигируемых по папкам category-разделов."""
    ext = extension_of(name)
    if ext in IMAGE_EXT:
        return "image"
    if ext in VIDEO_EXT:
        return "video"
    if ext in AUDIO_EXT:
        return "audio"
    if ext in TEXT_EXT | MARKDOWN_EXT | PDF_EXT:
        return "document"
    return "other"


def kind_of(name: str) -> str:
    ext = extension_of(name)
    if ext in IMAGE_EXT:
        return "image"
    if ext in VIDEO_EXT:
        return "video"
    if ext in AUDIO_EXT:
        return "audio"
    if ext in MARKDOWN_EXT:
        return "markdown"
    if ext in TEXT_EXT:
        return "text"
    if ext in PDF_EXT:
        return "pdf"
    if ext in RAW_EXT:
        return "raw"
    return "unknown"
