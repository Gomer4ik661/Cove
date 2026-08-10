//! FORMAT.md §6 — Data Blocks region. Каждый блок — самостоятельная запись
//! на диске: plaintext-заголовок (учёт места без расшифровки) + AEAD-шифртекст.
//! В этой фазе — только append (новые блоки дописываются в конец файла);
//! переиспользование места после удаления — Фаза 15 (компактификация), до
//! тех пор освобождённые блоки остаются орфанами (они всё равно зашифрованы,
//! поэтому "утечки" из этого не возникает — просто трата места на диске).

use crate::container::FileId;
use crate::crypto::{aead, keys};
use crate::error::{CoveError, Result};

/// file_id(8) + block_index(4) + nonce(24) + plaintext_len(4)
pub const HEADER_LEN: usize = 8 + 4 + aead::NONCE_LEN + 4;

pub struct BlockHeader {
    pub file_id: FileId,
    pub block_index: u32,
    pub nonce: [u8; aead::NONCE_LEN],
    pub plaintext_len: u32,
}

pub fn parse_header(buf: &[u8; HEADER_LEN]) -> BlockHeader {
    let nonce_start = 12;
    let nonce_end = nonce_start + aead::NONCE_LEN;
    BlockHeader {
        file_id: u64::from_le_bytes(buf[0..8].try_into().unwrap()),
        block_index: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
        nonce: buf[nonce_start..nonce_end].try_into().unwrap(),
        plaintext_len: u32::from_le_bytes(buf[nonce_end..nonce_end + 4].try_into().unwrap()),
    }
}

/// Длина блока целиком (header + ciphertext + tag) для данного размера
/// plaintext — нужно вызывающей стороне, чтобы дочитать блок после header'а.
pub fn total_len(plaintext_len: u32) -> usize {
    HEADER_LEN + plaintext_len as usize + aead::TAG_LEN
}

/// Кодирует один блок целиком, готовый к записи на диск как есть.
pub fn encode_block(file_id: FileId, block_index: u32, plaintext: &[u8], dek: &keys::Dek) -> Vec<u8> {
    let key = dek.subkey(keys::domain::DATA_BLOCKS);
    let nonce = aead::random_nonce();
    let ciphertext = aead::seal(&key, &nonce, plaintext).expect("seal never fails here");

    let mut bytes = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    bytes.extend_from_slice(&file_id.to_le_bytes());
    bytes.extend_from_slice(&block_index.to_le_bytes());
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&(plaintext.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&ciphertext);
    bytes
}

/// Декодирует блок из его полных байт на диске (header + ciphertext).
pub fn decode_block(full_bytes: &[u8], dek: &keys::Dek) -> Result<Vec<u8>> {
    if full_bytes.len() < HEADER_LEN {
        return Err(CoveError::FormatError {
            detail: "data block too short".into(),
        });
    }
    let header_buf: [u8; HEADER_LEN] = full_bytes[0..HEADER_LEN].try_into().unwrap();
    let header = parse_header(&header_buf);
    let ciphertext = &full_bytes[HEADER_LEN..];

    let key = dek.subkey(keys::domain::DATA_BLOCKS);
    aead::open(&key, &header.nonce, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::Dek;

    #[test]
    fn roundtrip() {
        let dek = Dek::generate();
        let plaintext = b"hello from a data block";
        let bytes = encode_block(7, 2, plaintext, &dek);
        assert_eq!(bytes.len(), total_len(plaintext.len() as u32));

        let header_buf: [u8; HEADER_LEN] = bytes[0..HEADER_LEN].try_into().unwrap();
        let header = parse_header(&header_buf);
        assert_eq!(header.file_id, 7);
        assert_eq!(header.block_index, 2);
        assert_eq!(header.plaintext_len, plaintext.len() as u32);

        let decoded = decode_block(&bytes, &dek).unwrap();
        assert_eq!(decoded, plaintext);
    }

    #[test]
    fn wrong_dek_fails() {
        let dek = Dek::generate();
        let other = Dek::generate();
        let bytes = encode_block(1, 0, b"secret", &dek);
        assert!(decode_block(&bytes, &other).is_err());
    }
}
