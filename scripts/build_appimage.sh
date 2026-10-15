#!/usr/bin/env bash
# Собирает Linux AppImage — один файл, который запускается двойным
# кликом/`./Cove-x86_64.AppImage` без установки Python/PySide6/venv
# (Фаза 16-17, ROADMAP.md: "упрощённый запуск для Linux").
#
# Порядок: cove_core_py.so (build_python_bindings.sh) → PyInstaller onefile
# (desktop/cove.spec, тот же, что и для голого бинарника) → AppDir → сборка
# самим AppImage через appimagetool (скачивается при отсутствии — тот же
# официальный релиз AppImage/appimagetool, что используется в CI-стиле для
# NDK в release.yml).
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

DESKTOP_DIR="desktop"
PACKAGING_DIR="$DESKTOP_DIR/packaging"
APPDIR="$PACKAGING_DIR/AppDir"
APPIMAGETOOL="$PACKAGING_DIR/appimagetool-x86_64.AppImage"

echo "== 1/5: cove_core_py.so =="
./scripts/build_python_bindings.sh

echo "== 2/5: cove-web-backend =="
./scripts/build_web_backend.sh

echo "== 3/5: PyInstaller onefile =="
# requirements.txt, а не хардкод "PySide6 pyinstaller" — иначе новые
# рантайм-зависимости (например, cryptography для механизма обновлений,
# Фаза 18) молча не попадали бы в свежий .venv при пересборке с нуля;
# нашлось вживую при первой реальной AppImage-сборке после их добавления.
if [[ ! -d "$DESKTOP_DIR/.venv" ]]; then
    python3 -m venv "$DESKTOP_DIR/.venv"
fi
"$DESKTOP_DIR/.venv/bin/pip" install --upgrade pip -q
"$DESKTOP_DIR/.venv/bin/pip" install -q -r "$DESKTOP_DIR/requirements.txt" pyinstaller
rm -rf "$DESKTOP_DIR/build" "$DESKTOP_DIR/dist"
(cd "$DESKTOP_DIR" && .venv/bin/pyinstaller --noconfirm cove.spec)

echo "== 4/5: AppDir =="
rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin"
cp "$DESKTOP_DIR/dist/Cove" "$APPDIR/usr/bin/Cove"
cp "$PACKAGING_DIR/cove.desktop" "$APPDIR/cove.desktop"
rsvg-convert -w 256 -h 256 "$PACKAGING_DIR/cove.svg" -o "$APPDIR/cove.png"
cat > "$APPDIR/AppRun" <<'EOF'
#!/bin/sh
HERE="$(dirname "$(readlink -f "$0")")"
exec "$HERE/usr/bin/Cove" "$@"
EOF
chmod +x "$APPDIR/AppRun"

echo "== 5/5: appimagetool =="
if [[ ! -x "$APPIMAGETOOL" ]]; then
    echo "appimagetool не найден, скачиваю официальный релиз..."
    curl -fL -o "$APPIMAGETOOL" \
        https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage
    chmod +x "$APPIMAGETOOL"
fi

OUT="$PACKAGING_DIR/Cove-x86_64.AppImage"
rm -f "$OUT"
# --appimage-extract-and-run — не полагаемся на то, что у пользователя,
# собирающего AppImage локально, обязательно есть смонтированный FUSE.
"$APPIMAGETOOL" --appimage-extract-and-run "$APPDIR" "$OUT"

echo "OK: $OUT"
