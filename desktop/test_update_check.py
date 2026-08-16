"""Реальные тесты app/update_check.py — без сети (мокаем HTTP-слой), но с
настоящей Ed25519-подписью через тот же keypair, что использует
scripts/sign_release.py. Запуск: `.venv/bin/python test_update_check.py`.
"""
import base64
import json
import sys
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app import update_check


# Тестовый keypair, сгенерированный так же, как в release-signing-key.pem.example
# (openssl genpkey -algorithm ed25519) — НЕ тот же ключ, что реальный
# release-signing-key.pem проекта (тот в .gitignore, тесты от него не зависят).
_TEST_PRIVATE_KEY = Ed25519PrivateKey.generate()
_TEST_PUBLIC_KEY_B64 = base64.b64encode(
    _TEST_PRIVATE_KEY.public_key().public_bytes_raw()
).decode("ascii")


def _sign(manifest_bytes: bytes) -> str:
    return base64.b64encode(_TEST_PRIVATE_KEY.sign(manifest_bytes)).decode("ascii")


def test_verify_manifest_signature_accepts_valid():
    with unittest.mock.patch.object(update_check, "RELEASE_PUBLIC_KEY_B64", _TEST_PUBLIC_KEY_B64):
        manifest = b'{"version": "1.2.3"}'
        update_check.verify_manifest_signature(manifest, _sign(manifest))  # не должно кинуть
    print("verify_manifest_signature accepts valid signature OK")


def test_verify_manifest_signature_rejects_tampered():
    with unittest.mock.patch.object(update_check, "RELEASE_PUBLIC_KEY_B64", _TEST_PUBLIC_KEY_B64):
        manifest = b'{"version": "1.2.3"}'
        sig = _sign(manifest)
        tampered = b'{"version": "9.9.9"}'
        try:
            update_check.verify_manifest_signature(tampered, sig)
            raise AssertionError("должно было кинуть UpdateCheckError на подделанный манифест")
        except update_check.UpdateCheckError:
            pass
    print("verify_manifest_signature rejects tampered manifest OK")


def test_verify_manifest_signature_rejects_wrong_key():
    # Подписано ДРУГИМ ключом, чем тот, которому мы доверяем — тег
    # "работоспособная подпись, но не тем ключом" не должен ничем
    # отличаться по результату от "подпись вообще не сошлась".
    other_key = Ed25519PrivateKey.generate()
    manifest = b'{"version": "1.2.3"}'
    wrong_sig = base64.b64encode(other_key.sign(manifest)).decode("ascii")
    with unittest.mock.patch.object(update_check, "RELEASE_PUBLIC_KEY_B64", _TEST_PUBLIC_KEY_B64):
        try:
            update_check.verify_manifest_signature(manifest, wrong_sig)
            raise AssertionError("должно было кинуть UpdateCheckError на чужую подпись")
        except update_check.UpdateCheckError:
            pass
    print("verify_manifest_signature rejects signature from wrong key OK")


def test_parse_version_ordering():
    assert update_check._parse_version("0.1.0") < update_check._parse_version("0.2.0")
    assert update_check._parse_version("1.0.0") > update_check._parse_version("0.99.99")
    assert update_check._parse_version("1.2.3") == update_check._parse_version("1.2.3")
    print("_parse_version ordering OK")


def _fake_manifest_and_sig(version: str) -> tuple[bytes, str]:
    manifest = json.dumps({"version": version, "assets": {}}, sort_keys=True).encode("utf-8")
    return manifest, _sign(manifest)


def test_check_for_updates_reports_newer_version_available():
    manifest_bytes, sig_b64 = _fake_manifest_and_sig("99.0.0")

    def fake_urlopen(req, timeout=None):
        url = req if isinstance(req, str) else req.full_url
        if "api.github.com" in url:
            body = json.dumps(
                {
                    "html_url": "https://github.com/OWNER/REPO/releases/tag/v99.0.0",
                    "assets": [
                        {"name": "release-manifest.json", "browser_download_url": "https://example/manifest"},
                        {"name": "release-manifest.json.sig", "browser_download_url": "https://example/sig"},
                    ],
                }
            ).encode("utf-8")
        elif url == "https://example/manifest":
            body = manifest_bytes
        elif url == "https://example/sig":
            body = sig_b64.encode("ascii")
        else:
            raise AssertionError(f"unexpected URL in test: {url}")
        return unittest.mock.MagicMock(
            __enter__=lambda s: s, __exit__=lambda *a: None, read=lambda: body
        )

    with unittest.mock.patch.object(update_check, "RELEASE_PUBLIC_KEY_B64", _TEST_PUBLIC_KEY_B64), \
         unittest.mock.patch.object(update_check, "CURRENT_VERSION", "0.1.0"), \
         unittest.mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
        result = update_check.check_for_updates()

    assert result.update_available is True
    assert result.latest_version == "99.0.0"
    assert "releases/tag/v99.0.0" in result.release_url
    print("check_for_updates detects newer version via mocked HTTP + real signature OK")


def test_check_for_updates_reports_up_to_date():
    manifest_bytes, sig_b64 = _fake_manifest_and_sig("0.1.0")

    def fake_urlopen(req, timeout=None):
        url = req if isinstance(req, str) else req.full_url
        if "api.github.com" in url:
            body = json.dumps(
                {
                    "html_url": "https://github.com/OWNER/REPO/releases/tag/v0.1.0",
                    "assets": [
                        {"name": "release-manifest.json", "browser_download_url": "https://example/manifest"},
                        {"name": "release-manifest.json.sig", "browser_download_url": "https://example/sig"},
                    ],
                }
            ).encode("utf-8")
        elif url == "https://example/manifest":
            body = manifest_bytes
        elif url == "https://example/sig":
            body = sig_b64.encode("ascii")
        else:
            raise AssertionError(f"unexpected URL in test: {url}")
        return unittest.mock.MagicMock(
            __enter__=lambda s: s, __exit__=lambda *a: None, read=lambda: body
        )

    with unittest.mock.patch.object(update_check, "RELEASE_PUBLIC_KEY_B64", _TEST_PUBLIC_KEY_B64), \
         unittest.mock.patch.object(update_check, "CURRENT_VERSION", "0.1.0"), \
         unittest.mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
        result = update_check.check_for_updates()

    assert result.update_available is False
    print("check_for_updates reports up-to-date when versions match OK")


def test_check_for_updates_rejects_tampered_manifest_end_to_end():
    manifest_bytes, sig_b64 = _fake_manifest_and_sig("99.0.0")
    tampered_bytes = manifest_bytes.replace(b"99.0.0", b"0.0.1")  # same length, forged downgrade attempt

    def fake_urlopen(req, timeout=None):
        url = req if isinstance(req, str) else req.full_url
        if "api.github.com" in url:
            body = json.dumps(
                {
                    "html_url": "https://github.com/OWNER/REPO/releases/tag/v99.0.0",
                    "assets": [
                        {"name": "release-manifest.json", "browser_download_url": "https://example/manifest"},
                        {"name": "release-manifest.json.sig", "browser_download_url": "https://example/sig"},
                    ],
                }
            ).encode("utf-8")
        elif url == "https://example/manifest":
            body = tampered_bytes  # атакующий подменил манифест, подпись — от оригинала
        elif url == "https://example/sig":
            body = sig_b64.encode("ascii")
        else:
            raise AssertionError(f"unexpected URL in test: {url}")
        return unittest.mock.MagicMock(
            __enter__=lambda s: s, __exit__=lambda *a: None, read=lambda: body
        )

    with unittest.mock.patch.object(update_check, "RELEASE_PUBLIC_KEY_B64", _TEST_PUBLIC_KEY_B64), \
         unittest.mock.patch.object(update_check, "CURRENT_VERSION", "0.1.0"), \
         unittest.mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
        try:
            update_check.check_for_updates()
            raise AssertionError("должно было кинуть UpdateCheckError на подделанный манифест")
        except update_check.UpdateCheckError:
            pass
    print("check_for_updates rejects tampered manifest end-to-end OK")


if __name__ == "__main__":
    test_verify_manifest_signature_accepts_valid()
    test_verify_manifest_signature_rejects_tampered()
    test_verify_manifest_signature_rejects_wrong_key()
    test_parse_version_ordering()
    test_check_for_updates_reports_newer_version_available()
    test_check_for_updates_reports_up_to_date()
    test_check_for_updates_rejects_tampered_manifest_end_to_end()
    print("ALL UPDATE_CHECK TESTS PASSED")
