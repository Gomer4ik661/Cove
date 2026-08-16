"""Проверка обновлений — ROADMAP.md Фаза 18, "механизм обновлений с
проверкой подписи". Осознанно НЕ автозамена бинарника (по прямому запросу
пользователя): только уведомление + ссылка на страницу релиза, скачивание и
установку пользователь делает сам. Ничего не скачивается автоматически,
кроме двух маленьких файлов (release-manifest.json + .sig) — сами
установочные файлы (десятки МБ) в этом сценарии не трогаем.

Реальная защита, которую даёт подпись именно здесь: GitHub Releases API
отдаётся по HTTPS, но подпись Ed25519 поверх release-manifest.json —
дополнительный слой, не полагающийся только на TLS до api.github.com,
который защищает от скомпрометированного CDN/зеркала и подтверждает, что
номер версии, которому мы вообще решаем доверять и показывать
пользователю, подписан тем же ключом, что и оригинальный релиз —
см. scripts/sign_release.py и docs/SECURITY_SELF_REVIEW.md.
"""
from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# Версия ЭТОГО приложения — держать в синхроне с `version` в корневом
# Cargo.toml при релизе (единого источника истины между Rust/Kotlin/Python
# в проекте нет, см. docs/ARCHITECTURE.md).
CURRENT_VERSION = "0.1.0"

# Публичный ключ (не секрет) — см. release-signing-key.pem.example.
# Должен совпадать с константой в android/.../UpdateChecker.kt.
RELEASE_PUBLIC_KEY_B64 = "OD0NGC0s4vSm5iAZyLuYsdlfRfcyWyHqX/qU2zAJRPw="

# TODO: заполнить реальным "owner/repo" перед первым релизом (репозиторий
# ещё не запушен на GitHub на момент написания — см. ROADMAP.md Фаза 18).
GITHUB_REPO = "OWNER/REPO"

_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
_REQUEST_TIMEOUT_S = 10


class UpdateCheckError(Exception):
    """Сеть недоступна, GitHub API недоступен, манифест не найден, подпись
    не сошлась — во всех случаях внятная причина, не молчаливый provал."""


@dataclass(frozen=True)
class UpdateResult:
    update_available: bool
    latest_version: str
    release_url: str


def _parse_version(v: str) -> tuple[int, ...]:
    """Простое X.Y.Z — без pre-release суффиксов, этого достаточно для
    версий, которые сами же и публикуем (scripts/sign_release.py)."""
    try:
        return tuple(int(p) for p in v.split("."))
    except ValueError as e:
        raise UpdateCheckError(f"не удалось разобрать номер версии: {v!r}") from e


def _http_get_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT_S) as resp:
            return json.loads(resp.read())
    except urllib.error.URLError as e:
        raise UpdateCheckError(f"не удалось связаться с GitHub: {e}") from e


def _http_get_bytes(url: str) -> bytes:
    try:
        with urllib.request.urlopen(url, timeout=_REQUEST_TIMEOUT_S) as resp:
            return resp.read()
    except urllib.error.URLError as e:
        raise UpdateCheckError(f"не удалось скачать {url}: {e}") from e


def verify_manifest_signature(manifest_bytes: bytes, signature_b64: str) -> None:
    """Кидает UpdateCheckError, если подпись не сошлась. Не возвращает
    bool — специально, чтобы вызывающий код не мог случайно проигнорировать
    False и продолжить работать с непроверенными данными."""
    try:
        signature = base64.b64decode(signature_b64.strip())
    except (ValueError, base64.binascii.Error) as e:
        raise UpdateCheckError(f"подпись не в base64: {e}") from e

    public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(RELEASE_PUBLIC_KEY_B64))
    try:
        public_key.verify(signature, manifest_bytes)
    except InvalidSignature as e:
        raise UpdateCheckError(
            "подпись release-manifest.json не сошлась — файл мог быть подделан "
            "или скачан из скомпрометированного источника, не доверяем"
        ) from e


def check_for_updates() -> UpdateResult:
    release = _http_get_json(_API_URL)
    release_url = release.get("html_url", f"https://github.com/{GITHUB_REPO}/releases/latest")
    assets = {a["name"]: a["browser_download_url"] for a in release.get("assets", [])}

    manifest_url = assets.get("release-manifest.json")
    sig_url = assets.get("release-manifest.json.sig")
    if manifest_url is None or sig_url is None:
        raise UpdateCheckError(
            "в последнем релизе нет release-manifest.json/.sig — "
            "либо релиз собран без scripts/sign_release.py, либо ещё не опубликован"
        )

    manifest_bytes = _http_get_bytes(manifest_url)
    signature_b64 = _http_get_bytes(sig_url).decode("ascii")

    verify_manifest_signature(manifest_bytes, signature_b64)

    manifest = json.loads(manifest_bytes)
    latest_version = manifest["version"]

    return UpdateResult(
        update_available=_parse_version(latest_version) > _parse_version(CURRENT_VERSION),
        latest_version=latest_version,
        release_url=release_url,
    )
