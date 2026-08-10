#!/usr/bin/env bash
# Собирает bindings/android (UniFFI) под все 4 Android ABI, генерирует
# Kotlin-биндинги и раскладывает всё по android/app/src/main — то, что
# build_python_bindings.sh делает для desktop, но под Android (Фаза 14,
# ROADMAP.md). Требует rustup-таргеты aarch64-linux-android,
# armv7-linux-androideabi, x86_64-linux-android, i686-linux-android
# (см. .cargo/config.toml в корне репозитория) и NDK по $ANDROID_NDK_HOME.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

ANDROID_APP="android/app/src/main"
declare -A TARGET_TO_ABI=(
    [aarch64-linux-android]=arm64-v8a
    [armv7-linux-androideabi]=armeabi-v7a
    [x86_64-linux-android]=x86_64
    [i686-linux-android]=x86
)

for target in "${!TARGET_TO_ABI[@]}"; do
    abi="${TARGET_TO_ABI[$target]}"
    echo "== $target ($abi) =="
    cargo build -p cove-android --target "$target" --release

    src="target/$target/release/libcove_core_uniffi.so"
    dst_dir="$ANDROID_APP/jniLibs/$abi"
    mkdir -p "$dst_dir"
    cp "$src" "$dst_dir/libcove_core_uniffi.so"
done

echo "== генерация Kotlin-биндингов =="
GEN_DIR="$(mktemp -d)"
cargo run -p cove-android --bin uniffi-bindgen -- generate \
    --library "target/aarch64-linux-android/release/libcove_core_uniffi.so" \
    --language kotlin \
    --out-dir "$GEN_DIR"

KOTLIN_DST="$ANDROID_APP/kotlin/uniffi/cove_core_uniffi"
mkdir -p "$KOTLIN_DST"
cp "$GEN_DIR"/uniffi/cove_core_uniffi/*.kt "$KOTLIN_DST/"
rm -rf "$GEN_DIR"

echo "OK: android/app/src/main/jniLibs/* и $KOTLIN_DST обновлены"
