//! FORMAT.md §5 — File Table, постранично, каждая страница отдельный AEAD-блок.

use crate::container::FileId;
use crate::crypto::{aead, keys};
use crate::error::{CoveError, Result};
use crate::format::wire::{push_bytes, push_string, push_u32, push_u64, push_u8, Reader};
use rayon::prelude::*;
use std::collections::HashSet;

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

/// `legacy_no_folder_category` — читать записи в раскладке, что была ДО
/// добавления `folder_category` (ROADMAP.md, "Правки по репорту
/// пользователя: папки в category-вкладках..."): контейнеры, созданные
/// более старой версией приложения, физически не содержат этот хвостовой
/// байт-флаг в каждой записи. `format_version` в заголовке при этом
/// изменении не был увеличен (см. `decode_page` ниже, почему различение
/// идёт не по нему), так что единственный надёжный признак — то, читаются
/// ли записи в новой раскладке ровно до конца буфера страницы, без
/// недостачи и без остатка (проверяется вызывающей стороной).
fn decode_entry(r: &mut Reader, legacy_no_folder_category: bool) -> Result<FileEntry> {
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
    let folder_category = if legacy_no_folder_category {
        None
    } else {
        let has_folder_category = r.u8()?;
        if has_folder_category == 1 { Some(r.string()?) } else { None }
    };
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

/// Пытается разобрать `count` записей из `plaintext` (сразу после префикса
/// длины) в заданной раскладке — успех только если разбор не споткнулся
/// НИ на одном поле И дочитал ровно до конца буфера, без остатка. "Ровно до
/// конца" — единственный доступный признак того, что раскладка угадана
/// верно: `format_version` в заголовке контейнера не был увеличен при
/// добавлении `folder_category` (ROADMAP.md), так что различать старые и
/// новые записи по нему нельзя (см. `decode_page`).
fn try_decode_entries(plaintext: &[u8], count: usize, legacy_no_folder_category: bool) -> Option<Vec<FileEntry>> {
    let mut r = Reader::new(plaintext);
    r.u32().ok()?; // count — уже известен вызывающей стороне, просто пропускаем префикс
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(decode_entry(&mut r, legacy_no_folder_category).ok()?);
    }
    if r.remaining() == 0 {
        Some(out)
    } else {
        None
    }
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

    let count = Reader::new(&plaintext).u32()? as usize;

    // Текущая раскладка (с folder_category) — пробуем первой, это верный
    // случай для всех страниц, записанных актуальным кодом. Только если она
    // не сходится ровно, откатываемся на раскладку до Фазы 18 (папки
    // category-вкладок): страница, записанная старой версией приложения,
    // физически не содержит хвостового байта-флага folder_category у КАЖДОЙ
    // записи, так что позиционный разбор в новой раскладке либо упирается в
    // конец буфера, либо съедает байты, принадлежащие следующей записи, — в
    // обоих случаях try_decode_entries(..., false) возвращает None. Смешение
    // версий внутри одной страницы невозможно: страница переписывается
    // целиком одним вызовом encode_page при любой правке (точечная запись,
    // ROADMAP.md "Фаза 2/6"), так что она либо целиком старая, либо целиком
    // новая.
    if let Some(entries) = try_decode_entries(&plaintext, count, false) {
        return Ok(entries);
    }
    if let Some(entries) = try_decode_entries(&plaintext, count, true) {
        return Ok(entries);
    }

    // Ни одна раскладка не сошлась — это уже настоящая ошибка (неверный
    // пароль привёл бы к провалу AEAD-тега ещё до этой точки, см. aead::open
    // выше), детали заведомо не в UI (error.rs).
    Err(CoveError::FormatError {
        detail: "file table page: entry layout not recognized (tried current and pre-folder_category legacy)".into(),
    })
}

/// Кодирует всю таблицу как набор страниц: `[page_count:u32]`, затем на
/// каждую страницу `[page_len:u32][page_bytes]`.
pub fn encode_file_table(entries: &[FileEntry], dek: &keys::Dek) -> Vec<u8> {
    let pages: Vec<&[FileEntry]> = split_into_pages(entries);

    // Каждая страница — независимый AEAD-блок (свой nonce), формат на диске
    // не меняется — меняется только то, что кодирование страниц идёт
    // параллельно, а не одна за другой (Фаза 15: ROADMAP.md, "Многопоточность").
    let encoded_pages: Vec<Vec<u8>> = pages.par_iter().map(|page| encode_page(page, dek)).collect();
    assemble_pages(&encoded_pages)
}

/// То же самое, что `encode_file_table`, но переиспользует уже закодированные
/// (зашифрованные) байты страниц из `cache` для страниц, чей номер НЕ входит
/// в `dirty` — реальная "точечная запись" из ROADMAP.md (Фаза 2/6): раньше
/// `commit()` перешифровывал ВСЮ File Table целиком при каждом изменении,
/// даже если правка коснулась одной записи в последней странице из тысяч.
/// AEAD-seal — не бесплатная операция (особенно на слабых Android-
/// устройствах), а страницы независимы (свой nonce у каждой) именно для
/// того, чтобы такое переиспользование было безопасным: страница на диске
/// остаётся ровно тем же самым шифртекстом, что и раньше, просто попадает в
/// новый файл по новому смещению — commit по-прежнему кладёт один цельный
/// самодостаточный блоб и атомарно переключает Commit Pointer, инвариант
/// crash-safety (FORMAT.md §6a) не меняется.
///
/// После вызова `cache` обновлён так, чтобы отражать ТЕКУЩУЮ раскладку
/// страниц (в т.ч. если число страниц изменилось) — следующий вызов может
/// полагаться на него без дополнительной подготовки.
pub fn encode_file_table_incremental(
    entries: &[FileEntry],
    dek: &keys::Dek,
    cache: &mut Vec<Vec<u8>>,
    dirty: &HashSet<usize>,
) -> Vec<u8> {
    let pages: Vec<&[FileEntry]> = split_into_pages(entries);

    let encoded_pages: Vec<Vec<u8>> = pages
        .par_iter()
        .enumerate()
        .map(|(i, page)| {
            if !dirty.contains(&i) {
                if let Some(cached) = cache.get(i) {
                    return cached.clone();
                }
            }
            encode_page(page, dek)
        })
        .collect();

    cache.clear();
    cache.extend(encoded_pages.iter().cloned());
    assemble_pages(&encoded_pages)
}

fn split_into_pages(entries: &[FileEntry]) -> Vec<&[FileEntry]> {
    if entries.is_empty() {
        vec![&[]]
    } else {
        entries.chunks(MAX_ENTRIES_PER_PAGE).collect()
    }
}

fn assemble_pages(encoded_pages: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    push_u32(&mut out, encoded_pages.len() as u32);
    for page_bytes in encoded_pages {
        push_u32(&mut out, page_bytes.len() as u32);
        push_bytes(&mut out, page_bytes);
    }
    out
}

/// Разбирает внешнюю framing-структуру блоба (`[page_count][page_len][page_bytes]...`)
/// на срезы отдельных страниц, БЕЗ попытки их расшифровать — общая часть
/// для строгого и щадящего (lenient) декодирования ниже.
fn split_page_slices(bytes: &[u8]) -> Result<Vec<&[u8]>> {
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
    Ok(page_slices)
}

pub fn decode_file_table(bytes: &[u8], dek: &keys::Dek) -> Result<Vec<FileEntry>> {
    let page_slices = split_page_slices(bytes)?;

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

/// Результат щадящей загрузки File Table (см. `decode_file_table_lenient`).
pub struct LenientLoad {
    /// Записи из всех страниц, которые удалось расшифровать.
    pub entries: Vec<FileEntry>,
    /// Сырые (ещё зашифрованные) байты каждой страницы в исходном порядке —
    /// используется как начальное состояние кэша для `encode_file_table_incremental`.
    pub page_cache: Vec<Vec<u8>>,
    /// Номера страниц (по порядку в блобе), которые НЕ прошли AEAD-
    /// аутентификацию — их содержимое безвозвратно потеряно, но остальные
    /// страницы всё равно доступны.
    pub corrupted_pages: Vec<usize>,
}

/// Как `decode_file_table`, но не отказывается открыть ВСЮ таблицу из-за
/// одной повреждённой страницы (ROADMAP.md, "Восстановление при частичном
/// повреждении File Table" — Фаза 2/17): постраничное разбиение (свой AEAD-
/// тег на страницу) уже давало техническую возможность для этого, не
/// хватало только вызывающего кода, который не считает первую же ошибку
/// фатальной для всего блоба. Внешняя framing-структура (длины страниц)
/// не аутентифицирована и разбирается до расшифровки, поэтому повреждение
/// СОДЕРЖИМОГО одной страницы не мешает найти и прочитать все остальные.
pub fn decode_file_table_lenient(bytes: &[u8], dek: &keys::Dek) -> Result<LenientLoad> {
    let page_slices = split_page_slices(bytes)?;

    let results: Vec<Result<Vec<FileEntry>>> =
        page_slices.par_iter().map(|page| decode_page(page, dek)).collect();

    let mut entries = Vec::new();
    let mut corrupted_pages = Vec::new();
    let mut page_cache = Vec::with_capacity(page_slices.len());
    for (i, (slice, result)) in page_slices.iter().zip(results).enumerate() {
        page_cache.push(slice.to_vec());
        match result {
            Ok(mut page_entries) => entries.append(&mut page_entries),
            Err(_) => corrupted_pages.push(i),
        }
    }

    Ok(LenientLoad {
        entries,
        page_cache,
        corrupted_pages,
    })
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

    fn many_entries(n: usize) -> Vec<FileEntry> {
        (0..n)
            .map(|i| {
                let mut e = sample_entry();
                e.file_id = i as u64;
                e.block_list = vec![];
                e
            })
            .collect()
    }

    /// Несколько последовательных commit'ов с точечными правками не должны
    /// перешифровывать страницы, которых правка не коснулась — иначе кэш
    /// бесполезен. Проверяем это не через тайминг (ненадёжно в CI), а через
    /// то, что закодированные байты НЕТРОНУТОЙ страницы побайтово совпадают
    /// с прошлым разом (не просто "то же содержимое" — то же самое
    /// зашифрованное значение, включая nonce, что доказывает, что seal()
    /// повторно не вызывался).
    #[test]
    fn incremental_encode_reuses_untouched_pages() {
        let dek = Dek::generate();
        let mut entries = many_entries(MAX_ENTRIES_PER_PAGE + 5); // 2 страницы
        let mut cache = Vec::new();
        let mut dirty: HashSet<usize> = (0..2).collect(); // первый вызов — обе "грязные"
        let bytes1 = encode_file_table_incremental(&entries, &dek, &mut cache, &dirty);
        assert_eq!(cache.len(), 2);
        let page0_first = cache[0].clone();
        let page1_first = cache[1].clone();

        // Правим одну запись во ВТОРОЙ странице — первая не тронута.
        entries[MAX_ENTRIES_PER_PAGE].name = "переименовано.jpg".to_string();
        dirty = HashSet::new();
        dirty.insert(1);
        let bytes2 = encode_file_table_incremental(&entries, &dek, &mut cache, &dirty);

        assert_eq!(cache[0], page0_first, "нетронутая страница 0 должна быть побайтово той же");
        assert_ne!(cache[1], page1_first, "изменённая страница 1 должна перешифроваться заново");

        // Итоговый блоб при этом честно содержит обновлённые данные.
        let decoded = decode_file_table(&bytes2, &dek).unwrap();
        assert_eq!(decoded[MAX_ENTRIES_PER_PAGE].name, "переименовано.jpg");
        assert_ne!(bytes1, bytes2);
    }

    /// Число страниц может уменьшиться (например, после `compact()`) —
    /// кэш не должен таскать за собой байты страниц, которых больше нет.
    #[test]
    fn incremental_encode_shrinks_cache_when_pages_removed() {
        let dek = Dek::generate();
        let big = many_entries(MAX_ENTRIES_PER_PAGE + 5);
        let mut cache = Vec::new();
        let dirty_all: HashSet<usize> = (0..2).collect();
        encode_file_table_incremental(&big, &dek, &mut cache, &dirty_all);
        assert_eq!(cache.len(), 2);

        let small = many_entries(3);
        let dirty: HashSet<usize> = std::iter::once(0).collect();
        encode_file_table_incremental(&small, &dek, &mut cache, &dirty);
        assert_eq!(cache.len(), 1);
    }

    /// Ядро "восстановления при частичном повреждении" (ROADMAP.md,
    /// Фаза 2/17): портим AEAD-шифртекст ровно одной страницы из трёх —
    /// щадящая загрузка обязана вернуть записи всех ОСТАЛЬНЫХ страниц, а не
    /// отказаться целиком, и честно сообщить номер потерянной страницы.
    #[test]
    fn lenient_decode_recovers_all_but_corrupted_page() {
        let dek = Dek::generate();
        let entries = many_entries(MAX_ENTRIES_PER_PAGE * 2 + 7); // 3 страницы
        let bytes = encode_file_table(&entries, &dek);

        // Структурно находим байты второй страницы и портим её шифртекст
        // (не префикс длины — иначе сломаем framing, а не содержимое).
        let mut r = Reader::new(&bytes);
        let page_count = r.u32().unwrap();
        assert_eq!(page_count, 3);
        let mut offsets = Vec::new();
        let mut cursor = 4usize;
        for _ in 0..page_count {
            let len = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
            offsets.push((cursor + 4, len));
            cursor += 4 + len;
        }
        let (page1_start, page1_len) = offsets[1];
        let mut forged = bytes.clone();
        // Портим байт где-то в середине шифртекста второй страницы (после
        // nonce, чтобы не наткнуться на короткую ошибку длины) — AEAD-тег
        // после этого не сойдётся.
        let flip_at = page1_start + page1_len / 2;
        forged[flip_at] ^= 0xFF;

        let result = decode_file_table_lenient(&forged, &dek).unwrap();
        assert_eq!(result.corrupted_pages, vec![1]);
        assert_eq!(result.page_cache.len(), 3);
        // Страницы 0 и 2 читаются полностью — потеряна только страница 1.
        let expected_recovered = entries.len() - (MAX_ENTRIES_PER_PAGE);
        assert_eq!(result.entries.len(), expected_recovered);
        let recovered_ids: HashSet<u64> = result.entries.iter().map(|e| e.file_id).collect();
        for e in entries.iter().take(MAX_ENTRIES_PER_PAGE) {
            assert!(recovered_ids.contains(&e.file_id), "страница 0 должна была уцелеть");
        }
        for e in entries.iter().skip(MAX_ENTRIES_PER_PAGE * 2) {
            assert!(recovered_ids.contains(&e.file_id), "страница 2 должна была уцелеть");
        }
    }

    /// Вручную кодирует запись в раскладке ДО добавления `folder_category`
    /// (зеркало `encode_entry`, но без последнего блока) — только для
    /// теста обратной совместимости `decode_page` ниже.
    fn encode_entry_legacy_pre_folder_category(e: &FileEntry, buf: &mut Vec<u8>) {
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
        // Нет байта folder_category — так выглядели записи, записанные
        // версией приложения до "Правки по репорту пользователя: папки в
        // category-вкладках..." (ROADMAP.md).
    }

    /// Регрессия на баг из живого репорта пользователя: контейнер, созданный
    /// более старой версией приложения (до появления `folder_category`),
    /// переставал открываться после обновления — `decode_entry` читал
    /// позиционно и упирался в конец буфера/съедал чужие байты, потому что
    /// `format_version` при этом изменении формата не был увеличен. Страница
    /// собрана здесь вручную в СТАРОЙ раскладке (см. `encode_page` для
    /// сравнения с текущей) — если этот тест падает, значит обратная
    /// совместимость снова сломана.
    #[test]
    fn legacy_entries_without_folder_category_still_open() {
        let dek = Dek::generate();
        let mut entry = sample_entry();
        entry.folder_category = None; // единственно возможное значение для старой раскладки

        let mut plaintext = Vec::new();
        push_u32(&mut plaintext, 1);
        encode_entry_legacy_pre_folder_category(&entry, &mut plaintext);

        let key = dek.subkey(keys::domain::FILE_TABLE);
        let nonce = aead::random_nonce();
        let ciphertext = aead::seal(&key, &nonce, &plaintext).unwrap();
        let mut page = Vec::with_capacity(aead::NONCE_LEN + ciphertext.len());
        page.extend_from_slice(&nonce);
        page.extend_from_slice(&ciphertext);

        let bytes = assemble_pages(&[page]);
        let decoded = decode_file_table(&bytes, &dek).unwrap();
        assert_eq!(decoded, vec![entry]);
    }

    /// Та же старая раскладка, но несколько записей на одной странице —
    /// подтверждает, что откат на легаси-разбор применяется ко ВСЕЙ странице
    /// разом, а не запись за записью (смешения версий внутри страницы не
    /// бывает, см. комментарий в `decode_page`).
    #[test]
    fn legacy_multi_entry_page_still_opens() {
        let dek = Dek::generate();
        let mut entries = many_entries(5);
        for e in &mut entries {
            e.folder_category = None;
        }

        let mut plaintext = Vec::new();
        push_u32(&mut plaintext, entries.len() as u32);
        for e in &entries {
            encode_entry_legacy_pre_folder_category(e, &mut plaintext);
        }

        let key = dek.subkey(keys::domain::FILE_TABLE);
        let nonce = aead::random_nonce();
        let ciphertext = aead::seal(&key, &nonce, &plaintext).unwrap();
        let mut page = Vec::with_capacity(aead::NONCE_LEN + ciphertext.len());
        page.extend_from_slice(&nonce);
        page.extend_from_slice(&ciphertext);

        let bytes = assemble_pages(&[page]);
        let decoded = decode_file_table(&bytes, &dek).unwrap();
        assert_eq!(decoded, entries);
    }

    /// Если не повреждено ничего — щадящая загрузка ведёт себя как обычная:
    /// все записи на месте, список повреждённых страниц пуст.
    #[test]
    fn lenient_decode_no_corruption_matches_strict() {
        let dek = Dek::generate();
        let entries = many_entries(10);
        let bytes = encode_file_table(&entries, &dek);
        let result = decode_file_table_lenient(&bytes, &dek).unwrap();
        assert!(result.corrupted_pages.is_empty());
        assert_eq!(result.entries.len(), entries.len());
    }
}
