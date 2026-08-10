# -*- mode: python ; coding: utf-8 -*-
# Фаза 16 (ROADMAP.md) — упаковка desktop-приложения в один исполняемый
# файл. cove_core_py.* — не стандартно именованное C-расширение (см.
# scripts/build_python_bindings.sh: плоское имя без ABI-тега), поэтому
# подключаем его явно через binaries, а не полагаемся на автообнаружение
# PyInstaller. Расширение платформозависимое: .so на Linux/macOS,
# .pyd на Windows (см. .github/workflows/release.yml, шаг windows-desktop).
import sys
from pathlib import Path

here = Path(SPECPATH)
ext = 'pyd' if sys.platform == 'win32' else 'so'
native_lib = here / f'cove_core_py.{ext}'
if not native_lib.exists():
    raise SystemExit(
        f'{native_lib} не найден — соберите биндинги: '
        f'cargo build --release -p cove-python, затем скопируйте результат '
        f'сюда под именем cove_core_py.{ext}'
    )

a = Analysis(
    ['main.py'],
    pathex=[str(here)],
    binaries=[(str(native_lib), '.')],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='Cove',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    # console=False только скрывает консольное окно на Windows — на
    # Linux/macOS никак не влияет на вывод в терминал, так что для
    # отладки ничего не теряется.
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
