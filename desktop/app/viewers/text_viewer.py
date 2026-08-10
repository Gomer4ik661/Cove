from PySide6.QtWidgets import QDialog, QTextEdit, QVBoxLayout


class TextViewerDialog(QDialog):
    def __init__(self, container, entry, is_markdown: bool, parent=None):
        super().__init__(parent)
        self.setWindowTitle(entry.name)
        self.resize(700, 600)

        data = bytes(container.read_at(entry.file_id, 0, entry.size))
        text = data.decode("utf-8", errors="replace")

        view = QTextEdit()
        view.setReadOnly(True)
        if is_markdown:
            view.setMarkdown(text)
        else:
            view.setPlainText(text)

        layout = QVBoxLayout(self)
        layout.addWidget(view)
