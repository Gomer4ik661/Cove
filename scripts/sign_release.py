#!/usr/bin/env python3
"""Строит release-manifest.json (версия + sha256 артефактов релиза) и
подписывает его Ed25519-ключом — ROADMAP.md Фаза 18, "механизм обновлений
с проверкой подписи". Подписываются РОВНО ТЕ БАЙТЫ, что попадут в
опубликованный release-manifest.json — намеренно, чтобы не зависеть от
того, одинаково ли Python/Kotlin канонически сериализуют JSON обратно
(десктоп и Android верифицируют подпись над сырыми байтами файла, как он
есть, а не над самостоятельно пересобранной сериализацией).

Использование:
    sign_release.py --version 0.1.0 --key release-signing-key.pem \
        --out-dir dist/ \
        --asset linux-appimage=desktop/packaging/Cove-x86_64.AppImage \
        --asset linux-binary=desktop/dist/Cove \
        --asset windows=desktop/dist/Cove.exe \
        --asset android=android/app/build/outputs/apk/release/app-release.apk

Пишет в --out-dir: release-manifest.json и release-manifest.json.sig
(подпись — 64 сырых байта Ed25519, закодированные в base64, одной строкой).
"""
import argparse
import base64
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_asset(spec: str) -> tuple[str, Path]:
    if "=" not in spec:
        raise SystemExit(f"--asset должен быть вида key=path, получено: {spec!r}")
    key, _, path_str = spec.partition("=")
    path = Path(path_str)
    if not path.is_file():
        raise SystemExit(f"asset {key!r}: файл не найден: {path}")
    return key, path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", required=True, help="Версия релиза, например 0.1.0")
    parser.add_argument("--key", required=True, type=Path, help="Путь к приватному Ed25519-ключу (PEM)")
    parser.add_argument("--out-dir", required=True, type=Path, help="Куда писать manifest + .sig")
    parser.add_argument(
        "--asset",
        action="append",
        required=True,
        metavar="KEY=PATH",
        help="Артефакт релиза, можно указывать несколько раз",
    )
    args = parser.parse_args()

    if not args.key.is_file():
        raise SystemExit(
            f"приватный ключ не найден: {args.key}\n"
            "Сгенерировать: openssl genpkey -algorithm ed25519 -out release-signing-key.pem\n"
            "(см. release-signing-key.pem.example в корне репозитория)"
        )

    assets = {}
    for spec in args.asset:
        key, path = parse_asset(spec)
        assets[key] = {"filename": path.name, "sha256": sha256_of(path)}
        print(f"  {key}: {path.name} sha256={assets[key]['sha256']}")

    manifest = {
        "version": args.version,
        "published_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "assets": assets,
    }
    # sort_keys — детерминированный вывод между запусками (для diff'а в CI-
    # логах и воспроизводимости), но подписываются именно эти байты как
    # есть — не пересобранная кем-то другим сериализация.
    manifest_bytes = (json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")

    with open(args.key, "rb") as f:
        private_key = load_pem_private_key(f.read(), password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise SystemExit(f"{args.key}: ожидался Ed25519-ключ, получен {type(private_key).__name__}")

    signature = private_key.sign(manifest_bytes)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = args.out_dir / "release-manifest.json"
    sig_path = args.out_dir / "release-manifest.json.sig"
    manifest_path.write_bytes(manifest_bytes)
    sig_path.write_text(base64.b64encode(signature).decode("ascii") + "\n")

    print(f"OK: {manifest_path}")
    print(f"OK: {sig_path}")


if __name__ == "__main__":
    main()
