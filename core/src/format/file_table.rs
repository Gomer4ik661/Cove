//! FORMAT.md §5 — File Table, постранично, каждая страница отдельный AEAD-блок.
//! Разбиение на страницы реализовано (`MAX_ENTRIES_PER_PAGE`), но логика
//! "переписывать только тронутую страницу" появится вместе с реальными
//! файловыми операциями в Фазе 6 — пока весь набор страниц перекодируется
//! заново при каждом commit (корректно, просто не оптимально).

use crate::container::FileId;
use crate::crypto::{aead, keys};
use crate::error::{CoveError, Result};
use crate::format::wire::{push_bytes, push_string, push_u32, push_u64, push_u8, Reader};
use rayon::prelude::*;

pub const MAX_ENTRIES_PER_PAGE: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FileFlags {
    pub trashed: bool,
    pub favorite: bool,
    /// Миниатюры и служебные записи — не показываются в библиотеке,
    /// но используют ту же инфраструктуру блоков (FORMAT.md §5).
    pub internal: bool,
    /// Папка — запись без содержимого (`block_list` всегда пуст), но
    /// участвующая в дереве через `parent_id`, как и обычные файлы.
    pub is_folder: bool,
}

impl FileFlags {
    fn to_u8(self) -> u8 {
        (self.trashed as u8)
            | ((self.favorite as u8) << 1)
            | ((self.internal as u8) << 2)
            | ((self.is_folder as u8) << 3)
    }
    fn from_u8(v: u8) -> Self {
        FileFlags {
            trashed: v & 0b0001 != 0,
            favorite: v & 0b0010 != 0,
            internal: v & 0b0100 != 0,
            is_folder: v & 0b1000 != 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FileEntry {
    pub file_id: FileId,
    pub parent_id: FileId,
    pub name: String,
    pub size: u64,
    pub created_at: u64,
    pub modified_at: u64,
    pub mime_hint: Option<String>,
    pub content_hash: [u8; 32], // BLAKE3
    /// Байтовые offset'ы в файле-контейнере, где начинается каждый блок
    /// данных (порядок — порядок блоков в файле). Пусто для папок.
    pub block_list: Vec<u64>,
    pub flags: FileFlags,
    /// Заполнено только у internal-записей (`flags.internal`) — file_id
    /// файла, миниатюрой которого эта запись является (ROADMAP.md Фаза 8).
    pub thumbnail_of: Option<FileId>,
    /// Заполнено только у папок (`flags.is_folder`) — категория вкладки
    /// (`"image"`/`"video"`/`"document"`/…), в которой папка была создана.
    /// По прямому запросу пользователя после Фазы 18: папка "привязывается"
    /// к категории на момент создания и дальше показывается только в этой
    /// вкладке-категории + в общей "Библиотеке", независимо от того, что
    /// потом в неё положат — не пересчитывается по фактическому содержимому.
    /// `None` — папка создана вне category-раздела (в "Библиотеке"), тогда
    /// показывается только там, ни в одной category-вкладке.
    pub folder_category: Option<String>,
}

fn encode_entry(e: &FileEntry, buf: &mut Vec<u8>) {
    push_u64(buf, e.file_id);
    push_u64(buf, e.parent_id);
    push_string(buf, &e.name);
    push_u64(buf, e.size);
    push_u64(buf, e.created_at);
    push_u64(buf, e.modified_at);
    match &e.mime_hint {
        Some(m) => {
            push_u8(buf, 1);
            push_string(buf, m);
        }
        None => push_u8(buf, 0),
    }
    push_bytes(buf, &e.content_hash);
    push_u32(buf, e.block_list.len() as u32);
    for b in &e.block_list {
        push_u64(buf, *b);
    }
    push_u8(buf, e.flags.to_u8());
    match e.thumbnail_of {
        Some(id) => {
            push_u8(buf, 1);
            push_u64(buf, id);
        }
        None => push_u8(buf, 0),
    }
    match &e.folder_category {
        Some(c) => {
            push_u8(buf, 1);
            push_string(buf, c);
        }
        None => push_u8(buf, 0),
    }
}

fn decode_entry(r: &mut Reader) -> Result<FileEntry> {
    let file_id = r.u64()?;
    let parent_id = r.u64()?;
    let name = r.string()?;
    let size = r.u64()?;
    let created_at = r.u64()?;
    let modified_at = r.u64()?;
    let has_mime = r.u8()?;
    let mime_hint = if has_mime == 1 { Some(r.string()?) } else { None };
    let content_hash: [u8; 32] = r.bytes(32)?.try_into().unwrap();
    let block_count = r.u32()? as usize;
    let mut block_list = Vec::with_capacity(block_count);
    for _ in 0..block_count {
        block_list.push(r.u64()?);
    }
    let flags = FileFlags::from_u8(r.u8()?);
    let has_thumbnail_of = r.u8()?;
    let thumbnail_of = if has_thumbnail_of == 1 { Some(r.u64()?) } else { None };
    let has_folder_category = r.u8()?;
    let folder_category = if has_folder_category == 1 { Some(r.string()?) } else { None };
    Ok(FileEntry {
        file_id,
        parent_id,
        name,
        size,
        created_at,
        modified_at,
        mime_hint,
        content_hash,
        block_list,
        flags,
        thumbnail_of,
        folder_category,
    })
}

fn encode_page(entries: &[FileEntry], dek: &keys::Dek) -> Vec<u8> {
    let mut plaintext = Vec::new();
    push_u32(&mut plaintext, entries.len() as u32);
    for e in entries {
        encode_entry(e, &mut plaintext);
    }

    let key = dek.subkey(keys::domain::FILE_TABLE);
    let nonce = aead::random_nonce();
    let ciphertext = aead::seal(&key, &nonce, &plaintext).expect("seal never fails here");

    let mut page = Vec::with_capacity(aead::NONCE_LEN + ciphertext.len());
    page.extend_from_slice(&nonce);
    page.extend_from_slice(&ciphertext);
    page
}

fn decode_page(page: &[u8], dek: &keys::Dek) -> Result<Vec<FileEntry>> {
    if page.len() < aead::NONCE_LEN {
        return Err(CoveError::FormatError {
            detail: "file table page too short".into(),
        });
    }
    let nonce: [u8; aead::NONCE_LEN] = page[0..aead::NONCE_LEN].try_into().unwrap();
    let key = dek.subkey(keys::domain::FILE_TABLE);
    let plaintext = aead::open(&key, &nonce, &page[aead::NONCE_LEN..])?;

    let mut r = Reader::new(&plaintext);
    let count = r.u32()? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(decode_entry(&mut r)?);
    }
    Ok(out)
}

/// Кодирует всю таблицу как набор страниц: `[page_count:u32]`, затем на
/// каждую страницу `[page_len:u32][page_bytes]`.
pub fn encode_file_table(entries: &[FileEntry], dek: &keys::Dek) -> Vec<u8> {
    let pages: Vec<&[FileEntry]> = if entries.is_empty() {
        vec![&[]]
    } else {
        entries.chunks(MAX_ENTRIES_PER_PAGE).collect()
    };

    // Каждая страница — независимый AEAD-блок (свой nonce), формат на диске
    // не меняется — меняется только то, что кодирование страниц идёт
    // параллельно, а не одна за другой (Фаза 15: ROADMAP.md, "Многопоточность").
    let encoded_pages: Vec<Vec<u8>> = pages.par_iter().map(|page| encode_page(page, dek)).collect();

    let mut out = Vec::new();
    push_u32(&mut out, encoded_pages.len() as u32);
    for page_bytes in encoded_pages {
        push_u32(&mut out, page_bytes.len() as u32);
        push_bytes(&mut out, &page_bytes);
    }
    out
}

pub fn decode_file_table(bytes: &[u8], dek: &keys::Dek) -> Result<Vec<FileEntry>> {
    let mut r = Reader::new(bytes);
    let page_count = r.u32()?;
    // page_count — часть внешней framing-структуры этого блоба, сама по
    // себе не защищена AEAD (каждая СТРАНИЦА защищена своим тегом, но не
    // этот префикс) — тот, у кого есть доступ на запись к файлу-контейнеру,
    // но нет пароля, может подменить только эти 4 байта. Каждая страница
    // занимает минимум 4 байта (свой префикс длины), так что заявленное
    // число страниц физически не может превышать bytes.len()/4 — проверяем
    // это ДО аллокации Vec, а не после (Фаза 17, тот же класс бага, что и
    // header.keyslots_len/data_blocks.plaintext_len).
    if page_count as u64 > bytes.len() as u64 / 4 {
        return Err(CoveError::FormatError {
            detail: "file table page_count implausibly large — corrupted container".into(),
        });
    }
    let mut page_slices = Vec::with_capacity(page_count as usize);
    for _ in 0..page_count {
        let page_len = r.u32()? as usize;
        page_slices.push(r.bytes(page_len)?);
    }

    // Разбор заголовков страниц — последовательный (Reader стейтфул), но
    // сам decode каждой страницы (AEAD-open + разбор записей) — независим
    // от соседних страниц, поэтому распараллелен (см. симметричный
    // комментарий в encode_file_table выше).
    let decoded_pages: Vec<Vec<FileEntry>> = page_slices
        .par_iter()
        .map(|page| decode_page(page, dek))
        .collect::<Result<Vec<_>>>()?;

    Ok(decoded_pages.into_iter().flatten().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::Dek;

    fn sample_entry() -> FileEntry {
        FileEntry {
            file_id: 42,
            parent_id: 0,
            name: "отпуск.jpg".to_string(),
            size: 123456,
            created_at: 1_700_000_000,
            modified_at: 1_700_000_100,
            mime_hint: Some("image/jpeg".to_string()),
            content_hash: [5u8; 32],
            block_list: vec![10, 11, 12],
            flags: FileFlags {
                trashed: false,
                favorite: true,
                internal: false,
                is_folder: false,
            },
            thumbnail_of: None,
            folder_category: None,
        }
    }

    #[test]
    fn empty_table_roundtrip() {
        let dek = Dek::generate();
        let bytes = encode_file_table(&[], &dek);
        let entries = decode_file_table(&bytes, &dek).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn single_entry_roundtrip() {
        let dek = Dek::generate();
        let entry = sample_entry();
        let bytes = encode_file_table(std::slice::from_ref(&entry), &dek);
        let entries = decode_file_table(&bytes, &dek).unwrap();
        assert_eq!(entries, vec![entry]);
    }

    #[test]
    fn entry_without_mime_roundtrip() {
        let dek = Dek::generate();
        let mut entry = sample_entry();
        entry.mime_hint = None;
        entry.block_list = vec![];
        let bytes = encode_file_table(std::slice::from_ref(&entry), &dek);
        let entries = decode_file_table(&bytes, &dek).unwrap();
        assert_eq!(entries, vec![entry]);
    }

    #[test]
    fn thumbnail_entry_roundtrip() {
        let dek = Dek::generate();
        let mut entry = sample_entry();
        entry.thumbnail_of = Some(42);
        entry.flags.internal = true;
        let bytes = encode_file_table(std::slice::from_ref(&entry), &dek);
        let entries = decode_file_table(&bytes, &dek).unwrap();
        assert_eq!(entries, vec![entry]);
    }

    #[test]
    fn pagination_splits_large_tables() {
        let dek = Dek::generate();
        let entries: Vec<FileEntry> = (0..(MAX_ENTRIES_PER_PAGE + 10))
            .map(|i| {
                let mut e = sample_entry();
                e.file_id = i as u64;
                e.block_list = vec![];
                e
            })
            .collect();
        let bytes = encode_file_table(&entries, &dek);
        let decoded = decode_file_table(&bytes, &dek).unwrap();
        assert_eq!(decoded.len(), entries.len());
    }

    /// Фаза 17 — page_count не защищён AEAD (это framing вокруг страниц, а
    /// не их содержимое), значит доступен для подмены тому, у кого есть
    /// доступ на запись к файлу, но нет пароля. Раньше `Vec::with_capacity`
    /// вызывался с этим значением напрямую — заведомо неправдоподобно
    /// большой page_count должен отклоняться до аллокации, а не после.
    #[test]
    fn forged_huge_page_count_rejected_not_oom() {
        let dek = Dek::generate();
        let bytes = encode_file_table(&[], &dek);
        let mut forged = bytes.clone();
        forged[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode_file_table(&forged, &dek).is_err());
    }
}
