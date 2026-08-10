import tempfile
from pathlib import Path

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices


def export_and_open_externally(container, entry) -> Path:
    """Экспортирует файл во временную папку ОС и открывает его приложением
    по умолчанию. Используется и контекстным меню "Открыть во внешнем
    приложении", и просмотрщиком как фолбэк для форматов без встроенного
    предпросмотра (PDF/RAW/неподдерживаемые — см. viewer_dialog.py)."""
    tmp_dir = Path(tempfile.mkdtemp(prefix="cove_"))
    tmp_path = tmp_dir / entry.name
    container.export_file(entry.file_id, str(tmp_path))
    QDesktopServices.openUrl(QUrl.fromLocalFile(str(tmp_path)))
    return tmp_path
