from PySide6.QtCore import QIODevice


class ContainerFileDevice(QIODevice):
    """Отдаёт содержимое файла из Container по требованию через read_at() —
    ни один расшифрованный байт не попадает на диск (ARCHITECTURE.md §4).
    Используется как источник для QMediaPlayer.setSourceDevice()."""

    def __init__(self, container, file_id: int, parent=None):
        super().__init__(parent)
        self._container = container
        self._file_id = file_id
        self._size = container.file_size(file_id)

    def isSequential(self) -> bool:
        return False

    def size(self) -> int:
        return self._size

    def readData(self, maxlen: int) -> bytes:
        offset = self.pos()
        if offset >= self._size or maxlen <= 0:
            return b""
        length = min(maxlen, self._size - offset)
        try:
            return bytes(self._container.read_at(self._file_id, offset, length))
        except Exception:  # noqa: BLE001 — QIODevice ожидает b"" при ошибке, не исключение
            return b""

    def writeData(self, data) -> int:
        return -1  # только чтение
