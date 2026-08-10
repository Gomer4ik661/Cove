from PySide6.QtGui import QImageReader
from PySide6.QtWidgets import QMessageBox

from . import file_kind
from .external_open import export_and_open_externally
from .viewers.image_viewer import ImageViewerDialog
from .viewers.media_viewer import MediaViewerDialog
from .viewers.text_viewer import TextViewerDialog

_UNSUPPORTED_REASONS = {
    "pdf": "просмотр PDF внутри Cove пока недоступен на этой системе (нет библиотеки Qt PDF)",
    "raw": "просмотр RAW-форматов пока не поддерживается",
}


def _supported_image_extensions() -> set[str]:
    return {bytes(f).decode().lower() for f in QImageReader.supportedImageFormats()}


def open_viewer(container, entry, parent) -> None:
    """Открывает подходящий просмотрщик по расширению файла (ROADMAP.md
    Фаза 7). Если встроенной поддержки нет — честно предлагает открыть
    файл во внешнем приложении, а не притворяется, что показала что-то."""
    kind = file_kind.kind_of(entry.name)

    if kind == "image" and file_kind.extension_of(entry.name) in _supported_image_extensions():
        ImageViewerDialog(container, entry, parent).exec()
        return
    if kind in ("video", "audio"):
        MediaViewerDialog(container, entry, kind == "video", parent).exec()
        return
    if kind in ("text", "markdown"):
        TextViewerDialog(container, entry, kind == "markdown", parent).exec()
        return

    _open_unsupported(container, entry, parent, kind)


def _open_unsupported(container, entry, parent, kind: str) -> None:
    reason = _UNSUPPORTED_REASONS.get(kind, "для этого типа файла ещё нет встроенного просмотрщика")
    answer = QMessageBox.question(
        parent,
        "Cove",
        f"Не удалось открыть «{entry.name}»: {reason}.\n\nОткрыть во внешнем приложении?",
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
    )
    if answer == QMessageBox.StandardButton.Yes:
        try:
            export_and_open_externally(container, entry)
        except Exception as exc:  # noqa: BLE001 — граница UI
            QMessageBox.critical(parent, "Cove", f"Не удалось открыть файл: {exc}")
