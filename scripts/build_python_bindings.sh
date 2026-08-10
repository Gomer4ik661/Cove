#!/usr/bin/env bash
# Собирает bindings/python (PyO3) и кладёт .so туда, откуда его увидит
# desktop/main.py. Временное решение до maturin (система под PEP 668
# externally-managed — pip install maturin не проходит без --break-system-packages,
# чего мы сознательно избегаем). Плоское имя `cove_core_py.so` — валидный
# суффикс расширения для CPython (входит в EXTENSION_SUFFIXES).
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

cargo build -p cove-python --release

SRC="target/release/libcove_core_py.so"
DST="desktop/cove_core_py.so"

if [[ ! -f "$SRC" ]]; then
    echo "error: $SRC not found — сборка не создала ожидаемый файл" >&2
    exit 1
fi

cp "$SRC" "$DST"
echo "OK: $DST обновлён"
