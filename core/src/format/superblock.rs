//! FORMAT.md §4 — Superblock: указатели на остальные регионы + счётчик версий.

use crate::crypto::{aead, keys};
use crate::error::{CoveError, Result};

const FIELD_COUNT: usize = 10;
pub const PLAINTEXT_LEN: usize = FIELD_COUNT * 8;
pub const BLOB_LEN: usize = aead::NONCE_LEN + PLAINTEXT_LEN + aead::TAG_LEN;

#[derive(Debug, Clone, Copy)]
pub struct Superblock {
    pub version_counter: u64,
    pub file_table_offset: u64,
    pub file_table_len: u64,
    /// Указатель на предыдущую валидную версию File Table — FORMAT.md §8,
    /// пункт 2 (запасной вариант при повреждении текущей).
    pub file_table_backup_offset: u64,
    pub search_index_offset: u64,
    pub search_index_len: u64,
    pub free_block_map_offset: u64,
    pub free_block_map_len: u64,
    pub login_log_offset: u64,
    pub login_log_len: u64,
}

impl Superblock {
    fn to_plaintext(self) -> [u8; PLAINTEXT_LEN] {
        let mut buf = [0u8; PLAINTEXT_LEN];
        let fields = [
            self.version_counter,
            self.file_table_offset,
            self.file_table_len,
            self.file_table_backup_offset,
            self.search_index_offset,
            self.search_index_len,
            self.free_block_map_offset,
            self.free_block_map_len,
            self.login_log_offset,
            self.login_log_len,
        ];
        for (i, f) in fields.iter().enumerate() {
            buf[i * 8..i * 8 + 8].copy_from_slice(&f.to_le_bytes());
        }
        buf
    }

    fn from_plaintext(buf: &[u8; PLAINTEXT_LEN]) -> Self {
        let mut v = [0u64; FIELD_COUNT];
        for (i, slot) in v.iter_mut().enumerate() {
            *slot = u64::from_le_bytes(buf[i * 8..i * 8 + 8].try_into().unwrap());
        }
        Superblock {
            version_counter: v[0],
            file_table_offset: v[1],
            file_table_len: v[2],
            file_table_backup_offset: v[3],
            search_index_offset: v[4],
            search_index_len: v[5],
            free_block_map_offset: v[6],
            free_block_map_len: v[7],
            login_log_offset: v[8],
            login_log_len: v[9],
        }
    }

    pub fn encode(&self, dek: &keys::Dek) -> [u8; BLOB_LEN] {
        let key = dek.subkey(keys::domain::SUPERBLOCK);
        let nonce = aead::random_nonce();
        let plaintext = self.to_plaintext();
        let ciphertext = aead::seal(&key, &nonce, &plaintext).expect("seal never fails here");

        let mut blob = [0u8; BLOB_LEN];
        blob[0..aead::NONCE_LEN].copy_from_slice(&nonce);
        blob[aead::NONCE_LEN..].copy_from_slice(&ciphertext);
        blob
    }

    pub fn decode(blob: &[u8; BLOB_LEN], dek: &keys::Dek) -> Result<Self> {
        let key = dek.subkey(keys::domain::SUPERBLOCK);
        let nonce: [u8; aead::NONCE_LEN] = blob[0..aead::NONCE_LEN].try_into().unwrap();
        let ciphertext = &blob[aead::NONCE_LEN..];
        let plaintext = aead::open(&key, &nonce, ciphertext)?;
        let arr: [u8; PLAINTEXT_LEN] = plaintext.as_slice().try_into().map_err(|_| {
            CoveError::FormatError {
                detail: "bad superblock plaintext length".into(),
            }
        })?;
        Ok(Self::from_plaintext(&arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::Dek;

    fn sample() -> Superblock {
        Superblock {
            version_counter: 5,
            file_table_offset: 100,
            file_table_len: 50,
            file_table_backup_offset: 10,
            search_index_offset: 0,
            search_index_len: 0,
            free_block_map_offset: 200,
            free_block_map_len: 20,
            login_log_offset: 300,
            login_log_len: 40,
        }
    }

    #[test]
    fn roundtrip() {
        let dek = Dek::generate();
        let blob = sample().encode(&dek);
        let decoded = Superblock::decode(&blob, &dek).unwrap();
        assert_eq!(decoded.version_counter, 5);
        assert_eq!(decoded.file_table_offset, 100);
        assert_eq!(decoded.free_block_map_len, 20);
        assert_eq!(decoded.login_log_offset, 300);
        assert_eq!(decoded.login_log_len, 40);
    }

    #[test]
    fn wrong_dek_fails() {
        let dek = Dek::generate();
        let other = Dek::generate();
        let blob = sample().encode(&dek);
        assert!(Superblock::decode(&blob, &other).is_err());
    }
}
