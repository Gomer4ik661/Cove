from PySide6.QtCore import QIODevice, QUrl, Qt
from PySide6.QtMultimedia import QAudioOutput, QMediaPlayer
from PySide6.QtMultimediaWidgets import QVideoWidget
from PySide6.QtWidgets import QDialog, QHBoxLayout, QLabel, QPushButton, QSlider, QVBoxLayout

from ..container_io_device import ContainerFileDevice


class MediaViewerDialog(QDialog):
    """Видео/аудио проигрыватель поверх ContainerFileDevice — плеер тянет
    байты через read_at() по требованию, ни один temp-файл не создаётся
    (ROADMAP.md Фаза 7, ARCHITECTURE.md §4)."""

    def __init__(self, container, entry, is_video: bool, parent=None):
        super().__init__(parent)
        self.setWindowTitle(entry.name)
        self.resize(720, 480 if is_video else 160)

        self._device = ContainerFileDevice(container, entry.file_id, self)
        self._device.open(QIODevice.OpenModeFlag.ReadOnly)

        self._player = QMediaPlayer(self)
        self._audio_output = QAudioOutput(self)
        self._player.setAudioOutput(self._audio_output)

        layout = QVBoxLayout(self)

        if is_video:
            video_widget = QVideoWidget()
            self._player.setVideoOutput(video_widget)
            layout.addWidget(video_widget, stretch=1)
        else:
            info_label = QLabel(entry.name)
            info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(info_label, stretch=1)

        controls = QHBoxLayout()
        self._play_button = QPushButton("▶")
        self._play_button.clicked.connect(self._toggle_play)
        self._position_slider = QSlider(Qt.Orientation.Horizontal)
        self._position_slider.sliderMoved.connect(self._player.setPosition)
        controls.addWidget(self._play_button)
        controls.addWidget(self._position_slider)
        layout.addLayout(controls)

        self._status_label = QLabel("")
        layout.addWidget(self._status_label)

        self._player.durationChanged.connect(lambda d: self._position_slider.setRange(0, d))
        self._player.positionChanged.connect(self._position_slider.setValue)
        self._player.errorOccurred.connect(self._on_error)

        self._player.setSourceDevice(self._device, QUrl(entry.name))
        self._player.play()

    def _toggle_play(self) -> None:
        if self._player.playbackState() == QMediaPlayer.PlaybackState.PlayingState:
            self._player.pause()
            self._play_button.setText("▶")
        else:
            self._player.play()
            self._play_button.setText("⏸")

    def _on_error(self, _error, error_string: str) -> None:
        self._status_label.setText(f"Ошибка воспроизведения: {error_string}")
        self._play_button.setEnabled(False)

    def closeEvent(self, event) -> None:
        self._player.stop()
        super().closeEvent(event)
