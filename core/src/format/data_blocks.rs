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

/// `file_id`+`block_index` как Associated Data — найдено при саморевью
/// крипто-части (docs/SECURITY_SELF_REVIEW.md): ключ шифрования (HKDF-
/// подключ `DATA_BLOCKS`) один на ВЕСЬ контейнер, общий для блоков всех
/// файлов. Без AAD, привязывающего ciphertext к конкретной (file_id,
/// block_index) позиции, AEAD-тег авторизует только "этот шифртекст был
/// запечатан под этим ключом с этим nonce" — но НЕ "этот шифртекст
/// принадлежит именно этому файлу и именно этой позиции в нём". Кто-то с
/// доступом на запись к файлу-контейнеру (без пароля) мог физически
/// переставить байты одного валидного блока на место другого (между
/// файлами или внутри одного файла) — тег остаётся валидным (это тот же
/// самый (key, nonce, ciphertext, tag), просто в другом месте на диске), и
/// при чтении жертва молча получила бы чужой расшифрованный контент вместо
/// ожидаемого, без единой ошибки. `content_hash` в File Table (BLAKE3
/// всего файла) на чтение НЕ проверяется — тоже не ловит такую подмену.
fn block_aad(file_id: FileId, block_index: u32) -> [u8; 12] {
    let mut aad = [0u8; 12];
    aad[0..8].copy_from_slice(&file_id.to_le_bytes());
    aad[8..12].copy_from_slice(&block_index.to_le_bytes());
    aad
}

/// Кодирует один блок целиком, готовый к записи на диск как есть.
pub fn encode_block(file_id: FileId, block_index: u32, plaintext: &[u8], dek: &keys::Dek) -> Vec<u8> {
    let key = dek.subkey(keys::domain::DATA_BLOCKS);
    let nonce = aead::random_nonce();
    let aad = block_aad(file_id, block_index);
    let ciphertext =
        aead::seal_aad(&key, &nonce, plaintext, &aad).expect("seal never fails here");

    let mut bytes = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    bytes.extend_from_slice(&file_id.to_le_bytes());
    bytes.extend_from_slice(&block_index.to_le_bytes());
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&(plaintext.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&ciphertext);
    bytes
}

/// Декодирует блок из его полных байт на диске (header + ciphertext).
///
/// `expected_file_id`/`expected_block_index` — ОБЯЗАНЫ приходить от
/// вызывающей стороны (из File Table и позиции в `block_list`, которым
/// доверяем — сама File Table целиком под AEAD), а НЕ из
/// `file_id`/`block_index`, прочитанных здесь же из заголовка блока: эти
/// поля лежат в открытом виде на диске и ничем не защищены (см.
/// `block_aad`) — использовать их для построения AAD, который тут же
/// сверяется, было бы бессмысленно (подмена подделывает оба поля разом).
pub fn decode_block(
    full_bytes: &[u8],
    dek: &keys::Dek,
    expected_file_id: FileId,
    expected_block_index: u32,
) -> Result<Vec<u8>> {
    if full_bytes.len() < HEADER_LEN {
        return Err(CoveError::FormatError {
            detail: "data block too short".into(),
        });
    }
    let header_buf: [u8; HEADER_LEN] = full_bytes[0..HEADER_LEN].try_into().unwrap();
    let header = parse_header(&header_buf);
    let ciphertext = &full_bytes[HEADER_LEN..];

    let key = dek.subkey(keys::domain::DATA_BLOCKS);
    let aad = block_aad(expected_file_id, expected_block_index);
    aead::open_aad(&key, &header.nonce, ciphertext, &aad)
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

        let decoded = decode_block(&bytes, &dek, 7, 2).unwrap();
        assert_eq!(decoded, plaintext);
    }

    #[test]
    fn wrong_dek_fails() {
        let dek = Dek::generate();
        let other = Dek::generate();
        let bytes = encode_block(1, 0, b"secret", &dek);
        assert!(decode_block(&bytes, &other, 1, 0).is_err());
    }

    /// Найдено при саморевью крипто-части (docs/SECURITY_SELF_REVIEW.md):
    /// до AAD-привязки этот же блок расшифровался бы УСПЕШНО под любой
    /// (file_id, block_index), потому что ключ общий на весь контейнер и
    /// nonce+ciphertext переезжают вместе как единое целое — то есть
    /// подмену/перестановку блоков между файлами AEAD-тег сам по себе не
    /// ловил. Теперь тот же валидный блок, прочитанный с ЧУЖИМ ожидаемым
    /// file_id/block_index (как было бы при физической подмене байт на
    /// диске), обязан провалиться.
    #[test]
    fn block_spliced_to_different_position_rejected() {
        let dek = Dek::generate();
        let bytes = encode_block(1, 0, b"secret of file 1", &dek);

        // Тот же самый файл, но "подъехавший" на позицию другого блока.
        assert!(decode_block(&bytes, &dek, 1, 1).is_err());
        // Другой файл целиком (классическая подмена: взять чужой валидный
        // блок и подставить вместо своего).
        assert!(decode_block(&bytes, &dek, 2, 0).is_err());

        // Контрольная проверка: с правильными координатами тот же блок
        // по-прежнему читается — это не "всё стало отклоняться", а именно
        // точечная привязка к позиции.
        assert!(decode_block(&bytes, &dek, 1, 0).is_ok());
    }
}
