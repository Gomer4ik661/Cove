#!/usr/bin/env bash
# Собирает web/backend (Axum/Tokio-сервер) под все 4 Android ABI и кладёт
# бинарник в jniLibs под видом libcove_web_backend.so — тот же трюк, что и
# для libcove_core_uniffi.so/build_android_bindings.sh, но здесь по другой
# причине: не JNA-загрузка, а обычный exec() (ProcessBuilder из
# WebServerService.kt) — каталогу нативных библиотек Android даёт exec-права
# на диске (после android.packaging.jniLibs.useLegacyPackaging=true в
# build.gradle.kts, иначе .so остаются только в mmap'е APK и не существуют
# как отдельный файл — проверено вживую на эмуляторе, ROADMAP.md "веб-морда
# в Android"). Требует тех же rustup-таргетов/NDK, что и
# build_android_bindings.sh.
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
    cargo build -p cove-web-backend --target "$target" --release

    src="target/$target/release/cove-web-backend"
    dst_dir="$ANDROID_APP/jniLibs/$abi"
    mkdir -p "$dst_dir"
    cp "$src" "$dst_dir/libcove_web_backend.so"
done

echo "OK: $ANDROID_APP/jniLibs/*/libcove_web_backend.so обновлены"
