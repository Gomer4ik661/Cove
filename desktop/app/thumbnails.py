from PySide6.QtCore import QBuffer, QByteArray, QEventLoop, QIODevice, QSize, Qt, QTimer, QUrl
from PySide6.QtGui import QPixmap
from PySide6.QtMultimedia import QMediaPlayer, QVideoSink

from .container_io_device import ContainerFileDevice

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


def generate_video_thumbnail_bytes(
    container, file_id: int, name: str = "video", max_size: int = THUMBNAIL_SIZE, timeout_ms: int = 5000
) -> bytes | None:
    """Достаёт один кадр из видео через QMediaPlayer/QVideoSink поверх
    ContainerFileDevice (тот же поток, что уже использует MediaViewerDialog
    — потоково, без временных файлов) и кодирует его в PNG, тем же путём,
    что и превью изображений. Синхронно (крутит вложенный QEventLoop, пока
    не придёт кадр или не истечёт timeout_ms) — тот же осознанно простой
    подход "один элемент за раз", что и у generate_thumbnail_bytes (см.
    комментарий в main_window.py._icon_for_entry): GUI-поток блокируется на
    время генерации, но PyO3-объект Container не рассчитан на параллельные
    вызовы из нескольких потоков, так что фоновый пул тут не вариант без
    более крупной переделки.

    Аудио не проигрывается — сюда никогда не передаётся QAudioOutput,
    без него QMediaPlayer сам не открывает звуковой выход."""
    device = ContainerFileDevice(container, file_id)
    if not device.open(QIODevice.OpenModeFlag.ReadOnly):
        return None

    player = QMediaPlayer()
    sink = QVideoSink()
    player.setVideoSink(sink)

    result: dict[str, bytes | None] = {"png": None}
    loop = QEventLoop()

    def finish() -> None:
        if loop.isRunning():
            loop.quit()

    def on_frame(frame) -> None:
        if result["png"] is not None or not frame.isValid():
            return
        image = frame.toImage()
        if image.isNull():
            return
        pixmap = QPixmap.fromImage(image)
        scaled = pixmap.scaled(
            QSize(max_size, max_size),
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        buffer_bytes = QByteArray()
        buffer = QBuffer(buffer_bytes)
        buffer.open(QIODevice.OpenModeFlag.WriteOnly)
        if scaled.save(buffer, "PNG"):
            result["png"] = bytes(buffer_bytes.data())
        finish()

    def on_status(status) -> None:
        # Кадр 0 у многих видео чёрный/пустой — отступаем чуть вперёд,
        # если знаем длительность, иначе просто играем с начала.
        if status == QMediaPlayer.MediaStatus.LoadedMedia:
            duration = player.duration()
            if duration > 0:
                player.setPosition(min(500, duration // 10))
            player.play()

    sink.videoFrameChanged.connect(on_frame)
    player.mediaStatusChanged.connect(on_status)
    player.errorOccurred.connect(lambda *_: finish())

    # Реальное имя (расширение) — как в viewers/media_viewer.py — помогает
    # FFmpeg-бэкенду увереннее определить контейнерный формат по QUrl, а не
    # только по сигнатуре байт.
    player.setSourceDevice(device, QUrl(name))
    QTimer.singleShot(timeout_ms, finish)
    loop.exec()

    player.stop()
    device.close()
    return result["png"]
