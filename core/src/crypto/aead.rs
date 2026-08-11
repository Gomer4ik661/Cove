//! XChaCha20-Poly1305 — единственный AEAD во всём проекте (FORMAT.md §0.4).
//! Случайный nonce на каждый вызов — 192 бита достаточно, чтобы не городить
//! счётчики между потоками/блоками.

use crate::error::{CoveError, Result};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use rand::RngCore;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;

pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

pub fn seal(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(XNonce::from_slice(nonce), plaintext)
        .map_err(|_| CoveError::FormatError {
            detail: "aead encrypt failed".into(),
        })
}

/// Ошибка тут структурно неотличима "неверный ключ" от "битые данные" —
/// вызывающий код сам решает, во что это превращать (AuthFailed при unwrap
/// DEK по паролю, FormatError при чтении File Table/Data Blocks) —
/// см. ARCHITECTURE.md §3.
pub fn open(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| CoveError::FormatError {
            detail: "aead decrypt failed (wrong key or corrupted data)".into(),
        })
}

/// То же, что [`seal`], но с Associated Data (AAD) — данные, которые
/// участвуют в вычислении тега аутентификации, но не шифруются и не
/// хранятся в ciphertext (вызывающий код обязан передать ТЕ ЖЕ байты при
/// расшифровке). Добавлено при саморевью крипто-части
/// (docs/SECURITY_SELF_REVIEW.md) для `format::data_blocks` — см. там же.
pub fn seal_aad(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(XNonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| CoveError::FormatError {
            detail: "aead encrypt failed".into(),
        })
}

/// Расшифровка с проверкой AAD — см. [`seal_aad`]. Несовпадение `aad` с тем,
/// что использовалось при `seal_aad`, всегда даёт ту же ошибку, что и
/// неверный ключ/битые данные — AEAD structurally не различает эти случаи.
pub fn open_aad(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| CoveError::FormatError {
            detail: "aead decrypt failed (wrong key, wrong position, or corrupted data)".into(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = [1u8; KEY_LEN];
        let nonce = random_nonce();
        let ct = seal(&key, &nonce, b"hello cove").unwrap();
        let pt = open(&key, &nonce, &ct).unwrap();
        assert_eq!(pt, b"hello cove");
    }

    #[test]
    fn tamper_detected() {
        let key = [1u8; KEY_LEN];
        let nonce = random_nonce();
        let mut ct = seal(&key, &nonce, b"hello cove").unwrap();
        *ct.last_mut().unwrap() ^= 0xFF;
        assert!(open(&key, &nonce, &ct).is_err());
    }

    #[test]
    fn aad_roundtrip() {
        let key = [1u8; KEY_LEN];
        let nonce = random_nonce();
        let ct = seal_aad(&key, &nonce, b"hello cove", b"context-a").unwrap();
        let pt = open_aad(&key, &nonce, &ct, b"context-a").unwrap();
        assert_eq!(pt, b"hello cove");
    }

    /// То, ради чего добавлен `seal_aad`/`open_aad` (см. `format::data_blocks`,
    /// docs/SECURITY_SELF_REVIEW.md) — тот же валидный (key, nonce, ciphertext,
    /// tag), но "пересаженный" в другой контекст (другой file_id/block_index в
    /// продакшене, здесь просто другая строка) обязан провалиться, даже
    /// притом что ключ и nonce те же самые и сам ciphertext не тронут.
    #[test]
    fn aad_mismatch_rejected() {
        let key = [1u8; KEY_LEN];
        let nonce = random_nonce();
        let ct = seal_aad(&key, &nonce, b"hello cove", b"context-a").unwrap();
        assert!(open_aad(&key, &nonce, &ct, b"context-b").is_err());
    }
}
