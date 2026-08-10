from PySide6.QtWidgets import QApplication

LIGHT_QSS = """
QWidget { background-color: #f5f5f7; color: #1c1c1e; }
QMainWindow, QDialog { background-color: #f5f5f7; }
QListWidget, QListView { background-color: #ffffff; border: 1px solid #d1d1d6; }
QListWidget::item:selected { background-color: #0a84ff; color: white; }
QPushButton { background-color: #ffffff; border: 1px solid #d1d1d6; border-radius: 6px; padding: 6px 14px; }
QPushButton:hover { background-color: #e8e8ed; }
QPushButton:default { background-color: #0a84ff; color: white; border: none; }
QLineEdit, QComboBox { background-color: #ffffff; border: 1px solid #d1d1d6; border-radius: 4px; padding: 4px; }
QStatusBar { background-color: #e8e8ed; }
"""

DARK_QSS = """
QWidget { background-color: #1c1c1e; color: #f2f2f7; }
QMainWindow, QDialog { background-color: #1c1c1e; }
QListWidget, QListView { background-color: #2c2c2e; border: 1px solid #3a3a3c; }
QListWidget::item:selected { background-color: #0a84ff; color: white; }
QPushButton { background-color: #2c2c2e; border: 1px solid #3a3a3c; border-radius: 6px; padding: 6px 14px; color: #f2f2f7; }
QPushButton:hover { background-color: #3a3a3c; }
QPushButton:default { background-color: #0a84ff; color: white; border: none; }
QLineEdit, QComboBox { background-color: #2c2c2e; border: 1px solid #3a3a3c; border-radius: 4px; padding: 4px; color: #f2f2f7; }
QStatusBar { background-color: #2c2c2e; }
"""


def apply_theme(app: QApplication, theme: str) -> None:
    app.setStyleSheet(DARK_QSS if theme == "dark" else LIGHT_QSS)
