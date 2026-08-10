import sys
from pathlib import Path

AUTOSTART_DIR = Path.home() / ".config" / "autostart"
DESKTOP_FILE = AUTOSTART_DIR / "cove.desktop"


def is_supported() -> bool:
    """Реализовано по XDG Autostart Specification — работает на Linux
    (GNOME/KDE/большинство DE). Windows/macOS — отдельные механизмы
    (реестр/LaunchAgents), не реализованы: не с чем автостартовать до
    настоящей упаковки в Фазе 16, ссылаться на текущий git-чекаут было бы
    нечестной заглушкой."""
    return sys.platform.startswith("linux")


def is_enabled() -> bool:
    return DESKTOP_FILE.exists()


def set_enabled(enabled: bool) -> None:
    if not is_supported():
        return
    if not enabled:
        DESKTOP_FILE.unlink(missing_ok=True)
        return

    AUTOSTART_DIR.mkdir(parents=True, exist_ok=True)
    main_script = Path(__file__).resolve().parent.parent / "main.py"
    exec_line = f'{sys.executable} "{main_script}"'
    content = (
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=Cove\n"
        f"Exec={exec_line}\n"
        "X-GNOME-Autostart-enabled=true\n"
    )
    DESKTOP_FILE.write_text(content, encoding="utf-8")
