#!/usr/bin/env bash
# Собирает web/backend (cove-web-backend) и кладёт бинарник туда, откуда
# его подхватит desktop/cove.spec при упаковке PyInstaller (см. комментарий
# там же) — по аналогии с build_python_bindings.sh для cove_core_py.so.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

cargo build -p cove-web-backend --release

if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    SRC="target/release/cove-web-backend.exe"
    DST="desktop/cove-web-backend.exe"
else
    SRC="target/release/cove-web-backend"
    DST="desktop/cove-web-backend"
fi

if [[ ! -f "$SRC" ]]; then
    echo "error: $SRC not found — сборка не создала ожидаемый файл" >&2
    exit 1
fi

cp "$SRC" "$DST"
echo "OK: $DST обновлён"
