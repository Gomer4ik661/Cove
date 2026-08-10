from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QSize, Qt
from PySide6.QtGui import QPixmap

THUMBNAIL_SIZE = 160


def generate_thumbnail_bytes(source_bytes: bytes, max_size: int = THUMBNAIL_SIZE) -> bytes | None:
    """Декодирует изображение и уменьшает его до миниатюры, отдаёт готовый
    PNG. Возвращает None, если Qt не смог декодировать исходные байты —
    вызывающая сторона не должна писать эти байты никуда на диск (ни
    исходные, ни промежуточные — только конечный PNG уходит в Container)."""
    pixmap = QPixmap()
    if not pixmap.loadFromData(source_bytes):
        return None

    scaled = pixmap.scaled(
        QSize(max_size, max_size),
        Qt.AspectRatioMode.KeepAspectRatio,
        Qt.TransformationMode.SmoothTransformation,
    )

    buffer_bytes = QByteArray()
    buffer = QBuffer(buffer_bytes)
    buffer.open(QIODevice.OpenModeFlag.WriteOnly)
    if not scaled.save(buffer, "PNG"):
        return None
    return bytes(buffer_bytes.data())


def pixmap_from_bytes(data: bytes) -> QPixmap:
    pixmap = QPixmap()
    pixmap.loadFromData(data)
    return pixmap
