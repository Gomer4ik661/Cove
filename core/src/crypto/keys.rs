//! DEK-генерация, envelope-обёртка (wrap/unwrap) и HKDF-разделение подключей
//! по доменам — реализация принципов FORMAT.md §0.2 и §0.3.

use crate::crypto::aead;
use crate::error::{CoveError, Result};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::{Zeroizing, ZeroizeOnDrop};

pub const DEK_LEN: usize = 32;

/// Домены HKDF-подключей — единый источник истины строк-доменов, чтобы
/// не разъезжались между писателем и читателем (FORMAT.md §0.3).
pub mod domain {
    pub const SUPERBLOCK: &str = "cove.superblock.v1";
    pub const FILE_TABLE: &str = "cove.filetable.v1";
    pub const SEARCH_INDEX: &str = "cove.searchindex.v1";
    pub const DATA_BLOCKS: &str = "cove.datablocks.v1";
    pub const FREE_MAP: &str = "cove.freemap.v1";
    pub const LOGIN_LOG: &str = "cove.loginlog.v1";
}

/// Data Encryption Key. Обнуляется в памяти при Drop — THREAT_MODEL.md §2.3.
#[derive(ZeroizeOnDrop)]
pub struct Dek([u8; DEK_LEN]);

impl Dek {
    pub fn generate() -> Self {
        let mut bytes = [0u8; DEK_LEN];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Dek(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; DEK_LEN] {
        &self.0
    }

    /// Подключ под конкретный домен использования (File Table / индекс /
    /// блоки данных / superblock) — FORMAT.md §0.3. Домены-строки — из
    /// FORMAT.md, менять их означает менять формат, а не просто код.
    ///
    /// `Zeroizing<[u8; 32]>`, не голый массив — найдено при саморевью
    /// крипто-части (docs/SECURITY_SELF_REVIEW.md): это тот самый ключ,
    /// которым `aead::seal`/`open` шифрует каждую страницу File Table,
    /// каждый блок данных и т.д. — вызывается на каждую операцию, а раньше
    /// ничем не зачищался по выходу из скоупа, в отличие от самого `Dek`.
    pub fn subkey(&self, domain: &str) -> Zeroizing<[u8; 32]> {
        let hk = Hkdf::<Sha256>::new(None, &self.0);
        let mut out = Zeroizing::new([0u8; 32]);
        hk.expand(domain.as_bytes(), &mut *out)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        out
    }
}

#[derive(Debug, Clone)]
pub struct WrappedDek {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; aead::NONCE_LEN],
}

pub fn wrap_dek(dek: &Dek, kek: &[u8; crate::crypto::kdf::KEK_LEN]) -> Result<WrappedDek> {
    let nonce = aead::random_nonce();
    let ciphertext = aead::seal(kek, &nonce, &dek.0)?;
    Ok(WrappedDek { ciphertext, nonce })
}

pub fn unwrap_dek(
    wrapped: &WrappedDek,
    kek: &[u8; crate::crypto::kdf::KEK_LEN],
) -> Result<Dek> {
    // Любая ошибка тут — по построению "неверный пароль", т.к. kek уже
    // получен из пароля выше по стеку. FORMAT.md §3 / ARCHITECTURE.md §3.
    let plaintext =
        aead::open(kek, &wrapped.nonce, &wrapped.ciphertext).map_err(|_| CoveError::AuthFailed)?;
    let bytes: [u8; DEK_LEN] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| CoveError::AuthFailed)?;
    Ok(Dek(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf;

    #[test]
    fn wrap_unwrap_roundtrip() {
        let dek = Dek::generate();
        let salt = [7u8; kdf::SALT_LEN];
        let kek = kdf::derive_kek(b"correct horse battery staple", &salt, kdf::KdfParams::default())
            .unwrap();

        let wrapped = wrap_dek(&dek, &kek).unwrap();
        let unwrapped = unwrap_dek(&wrapped, &kek).unwrap();

        assert_eq!(dek.as_bytes(), unwrapped.as_bytes());
    }

    #[test]
    fn wrong_password_fails_cleanly() {
        let dek = Dek::generate();
        let salt = [7u8; kdf::SALT_LEN];
        let params = kdf::KdfParams::default();
        let kek = kdf::derive_kek(b"right password", &salt, params).unwrap();
        let wrapped = wrap_dek(&dek, &kek).unwrap();

        let wrong_kek = kdf::derive_kek(b"wrong password", &salt, params).unwrap();
        assert!(matches!(
            unwrap_dek(&wrapped, &wrong_kek),
            Err(CoveError::AuthFailed)
        ));
    }

    #[test]
    fn subkeys_differ_by_domain() {
        let dek = Dek::generate();
        assert_ne!(
            dek.subkey("cove.filetable.v1"),
            dek.subkey("cove.datablocks.v1")
        );
    }
}
