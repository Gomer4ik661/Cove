from PySide6.QtGui import QFont
from PySide6.QtWidgets import QCheckBox, QDialog, QDialogButtonBox, QLabel, QTextEdit, QVBoxLayout


class RecoveryPhraseDialog(QDialog):
    """Показывает recovery-фразу РОВНО ОДИН РАЗ (FORMAT.md: "нигде
    автоматически" — приложение её не сохраняет и не может показать снова)."""

    def __init__(self, phrase: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Recovery-фраза")
        self.setMinimumWidth(480)
        self.setModal(True)

        warning = QLabel(
            "Сохраните эту фразу в надёжном месте. Это единственный способ "
            "восстановить доступ к хранилищу, если вы забудете пароль. "
            "Cove не хранит и не показывает её повторно."
        )
        warning.setWordWrap(True)

        phrase_view = QTextEdit()
        phrase_view.setReadOnly(True)
        phrase_view.setPlainText(phrase)
        font = QFont("Monospace")
        font.setPointSize(13)
        font.setStyleHint(QFont.StyleHint.TypeWriter)
        phrase_view.setFont(font)
        phrase_view.setFixedHeight(90)

        self._confirm_checkbox = QCheckBox("Я сохранил(а) фразу в надёжном месте")
        self._confirm_checkbox.stateChanged.connect(self._update_ok_enabled)

        self._buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        self._buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(False)
        self._buttons.accepted.connect(self.accept)

        layout = QVBoxLayout(self)
        layout.addWidget(warning)
        layout.addWidget(phrase_view)
        layout.addWidget(self._confirm_checkbox)
        layout.addWidget(self._buttons)

    def _update_ok_enabled(self) -> None:
        self._buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(
            self._confirm_checkbox.isChecked()
        )
