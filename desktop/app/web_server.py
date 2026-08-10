"""Запуск/остановка cove-web-backend как дочернего процесса — Фаза 13
(ROADMAP.md). Веб-доступ по умолчанию выключен: сервер не запускается сам
по себе, только по явному нажатию "Запустить" во вкладке "Веб" настроек.

ВАЖНО (задокументировано и в ROADMAP.md, и в UI вкладки "Веб"): Core пока не
делает file-level advisory locking (flock) над .slr-файлом — если открыть
одно и то же хранилище одновременно в десктопе и через веб-сервер и
редактировать в обоих местах, последняя закоммиченная запись молча
перезапишет более раннюю. Реальная защита — межпроцессная блокировка в
Core — осознанно вынесена за рамки Фазы 13 (см. ROADMAP.md), это отдельная
по объёму задача, а не недосмотр.
"""

import subprocess
from pathlib import Path
from typing import Optional


def find_binary() -> Optional[Path]:
    here = Path(__file__).resolve()
    repo_root = here.parents[2]  # desktop/app/web_server.py -> desktop -> repo root
    for profile in ("release", "debug"):
        candidate = repo_root / "target" / profile / "cove-web-backend"
        if candidate.exists():
            return candidate
    return None


class WebServerManager:
    """Владеет максимум одним дочерним процессом cove-web-backend."""

    def __init__(self) -> None:
        self._process: Optional[subprocess.Popen] = None
        self._port: Optional[int] = None

    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def port(self) -> Optional[int]:
        return self._port if self.is_running() else None

    def start(self, container_path: str, port: int) -> tuple[bool, str]:
        if self.is_running():
            return False, "Веб-сервер уже запущен."

        binary = find_binary()
        if binary is None:
            return False, (
                "Бинарник cove-web-backend не найден. Соберите его: "
                "cargo build -p cove-web-backend (или --release)."
            )

        try:
            self._process = subprocess.Popen(
                [
                    str(binary),
                    "--container",
                    container_path,
                    "--bind",
                    f"0.0.0.0:{port}",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError as exc:
            self._process = None
            return False, f"Не удалось запустить процесс: {exc}"

        self._port = port
        return True, ""

    def stop(self) -> None:
        if self._process is None:
            return
        self._process.terminate()
        try:
            self._process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait(timeout=5)
        self._process = None
        self._port = None
