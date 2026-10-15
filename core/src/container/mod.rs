//! Публичный фасад Core — ARCHITECTURE.md §2. Единственная точка входа для
//! всех биндингов (Python/Kotlin/Web); только простые типы через границу.

mod session;
pub use session::Session;

use crate::crypto::{kdf, keys};
use crate::error::{CoveError, Result};
use crate::format::commit::{self, CommitPointer};
use crate::format::data_blocks;
use crate::format::file_table::{self, FileEntry};
use crate::format::free_map;
use crate::format::header::{self, Header};
use crate::format::keyslots::{self, Keyslot, Role, SlotType};
use crate::format::login_log;
use crate::format::superblock::{self, Superblock};
use crate::search::SearchQuery;
use crate::users::LoginLogEntry;

use rand::RngCore;
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub type FileId = u64;

/// По конвенции — корневая папка контейнера, отдельной записи в File Table
/// для неё нет.
pub const ROOT_FOLDER_ID: FileId = 0;

/// Имя, под которым разблокировка через recovery-фразу попадает в журнал
/// входов — честно отражает, что это не конкретный пользователь.
const RECOVERY_IDENTITY: &str = "recovery";

const FORMAT_VERSION: u16 = 1;
const DEFAULT_BLOCK_SIZE: u32 = 4 * 1024 * 1024;

pub struct RecoveryPhrase(pub String);

/// Контейнер до ввода пароля — доступны только метаданные keyslot'ов.
pub struct LockedContainer {
    path: PathBuf,
    header: Header,
    keyslots: Vec<Option<Keyslot>>,
}

impl LockedContainer {
    pub fn open(path: &str) -> Result<Self> {
        let mut file = File::open(path)?;

        let mut header_buf = [0u8; header::HEADER_LEN];
        file.read_exact(&mut header_buf)?;
        let header = Header::parse(&header_buf)?;

        // header — plaintext, без криптографической аутентификации (только
        // самосогласованный checksum, который злоумышленник может
        // пересчитать под любые значения полей) — keyslots_len нельзя
        // напрямую доверять как размер аллокации до какой-либо проверки.
        // Keyslots region всегда фиксированного размера, так что сверяем
        // заявленную длину с единственно верной константой вместо того,
        // чтобы allocate'ить `vec![0u8; header.keyslots_len as usize]` —
        // иначе специально сфабрикованный .slr с огромным keyslots_len
        // валит процесс OOM-абортом ещё до ввода пароля (Фаза 17,
        // найдено при разборе парсера на предмет fuzzing-целей).
        let expected_keyslots_len = (keyslots::SLOT_LEN * keyslots::CAPACITY) as u64;
        if header.keyslots_len != expected_keyslots_len {
            return Err(CoveError::FormatError {
                detail: "header keyslots_len does not match expected fixed size".into(),
            });
        }

        file.seek(SeekFrom::Start(header.keyslots_offset))?;
        let mut keyslots_buf = vec![0u8; expected_keyslots_len as usize];
        file.read_exact(&mut keyslots_buf)?;
        let keyslots = keyslots::parse_region(&keyslots_buf)?;

        Ok(LockedContainer {
            path: PathBuf::from(path),
            header,
            keyslots,
        })
    }

    pub fn list_usernames(&self) -> Vec<String> {
        self.keyslots
            .iter()
            .flatten()
            .filter(|s| s.slot_type == SlotType::User)
            .map(|s| s.username.clone())
            .collect()
    }

    pub fn unlock(&self, username: &str, password: &str) -> Result<Container> {
        // Намеренно одна и та же ошибка что при неверном пароле — не даём
        // enumerate пользователей по разнице в ответе (THREAT_MODEL.md §2.1,
        // ARCHITECTURE.md §3).
        //
        // Найдено при саморевью крипто-части (docs/SECURITY_SELF_REVIEW.md):
        // одинаковое СОДЕРЖИМОЕ ошибки не значит одинаковое ВРЕМЯ ответа.
        // При существующем username путь ниже прогоняет Argon2id (осознанно
        // ~100мс+, FORMAT.md §3), при несуществующем — раньше возвращал
        // AuthFailed мгновенно, до Argon2id. Для Web-бэкона
        // (THREAT_MODEL.md §2.4, самая широкая поверхность атаки в
        // проекте) это готовый timing-oracle для перечисления валидных
        // username по задержке ответа, даже когда текст ошибки одинаковый.
        // Прогоняем ту же по стоимости Argon2id-операцию и на "не найден",
        // чтобы оба пути стоили сопоставимо по времени.
        match self
            .keyslots
            .iter()
            .flatten()
            .find(|s| s.slot_type == SlotType::User && s.username == username)
        {
            Some(slot) => self.unlock_slot(slot, password.as_bytes(), username),
            None => {
                let dummy_salt = [0u8; kdf::SALT_LEN];
                let _ = kdf::derive_kek(password.as_bytes(), &dummy_salt, kdf::KdfParams::default());
                Err(CoveError::AuthFailed)
            }
        }
    }

    pub fn unlock_with_recovery(&self, phrase: &str) -> Result<Container> {
        let slot = self
            .keyslots
            .iter()
            .flatten()
            .find(|s| s.slot_type == SlotType::Recovery)
            .ok_or(CoveError::AuthFailed)?;
        self.unlock_slot(slot, phrase.trim().as_bytes(), RECOVERY_IDENTITY)
    }

    fn unlock_slot(&self, slot: &Keyslot, password: &[u8], identity: &str) -> Result<Container> {
        let kek = kdf::derive_kek(password, &slot.kdf_salt, slot.kdf_params)?;
        let dek = keys::unwrap_dek(&slot.wrapped_dek, &kek)?;
        let role = slot.role;

        let mut file = File::open(&self.path)?;
        let (pointer, _active_offset) = read_valid_commit_pointer(&mut file, &self.header)?;

        let mut sb_blob = [0u8; superblock::BLOB_LEN];
        file.seek(SeekFrom::Start(pointer.superblock_offset))?;
        file.read_exact(&mut sb_blob)?;
        let sb = Superblock::decode(&sb_blob, &dek)?;

        let table_load = read_file_table_with_recovery(&mut file, &sb, &dek)?;
        let free_blocks = read_free_map(&mut file, &sb, &dek)?;
        let mut log = read_login_log(&mut file, &sb, &dek)?;
        log.push(LoginLogEntry {
            username: identity.to_string(),
            timestamp: now_unix(),
            success: true,
        });

        let next_file_id = table_load
            .entries
            .iter()
            .map(|e| e.file_id)
            .max()
            .map(|m| m + 1)
            .unwrap_or(1);

        Ok(Container {
            path: self.path.clone(),
            header: self.header,
            session: Session { dek },
            superblock: sb,
            file_table: table_load.entries,
            free_blocks,
            keyslots: self.keyslots.clone(),
            login_log: log,
            current_username: identity.to_string(),
            current_role: role,
            next_file_id,
            // Запись в login_log (выше) не считается "грязным" состоянием
            // для целей conflict-проверки в commit() — см. комментарий у
            // поля dirty.
            dirty: false,
            file_table_page_cache: table_load.page_cache,
            dirty_pages: HashSet::new(),
            lost_file_table_pages: table_load.corrupted_pages,
            orphans_created: false,
        })
    }
}

/// Разблокированная сессия.
pub struct Container {
    path: PathBuf,
    header: Header,
    session: Session,
    superblock: Superblock,
    file_table: Vec<FileEntry>,
    free_blocks: Vec<u64>,
    keyslots: Vec<Option<Keyslot>>,
    login_log: Vec<LoginLogEntry>,
    current_username: String,
    current_role: Role,
    /// Следующий свободный `FileId` — кэш, чтобы не пересчитывать
    /// `max(file_table) + 1` линейным сканом на каждый импорт (Фаза 15:
    /// на 100k+ файлах это давало O(n²) при массовом импорте, реальный
    /// профайлинг показал именно это, а не крипто-операции или fsync).
    next_file_id: FileId,
    /// Есть ли в этой сессии несохранённые изменения содержимого (File
    /// Table/Free Map) — НЕ считается изменением сама по себе запись в
    /// login_log при unlock(): иначе абсолютно любая, даже чисто читающая
    /// сессия считалась бы "грязной" и conflict-проверка в commit() ловила
    /// бы её же собственный безобидный commit как настоящий конфликт (см.
    /// комментарий у CoveError::Conflict и commit()). Выставляется
    /// мутирующими методами, сбрасывается в false после успешного commit().
    dirty: bool,
    /// Кэш уже закодированных (зашифрованных) страниц File Table — с
    /// прошлого unlock()/reload()/commit()/compact(). Позволяет `commit()`
    /// не перешифровывать страницы, которых не коснулась текущая порция
    /// правок (ROADMAP.md — "точечная запись File Table"), см.
    /// `file_table::encode_file_table_incremental`.
    file_table_page_cache: Vec<Vec<u8>>,
    /// Номера страниц (индекс = позиция в `file_table`, делённая на
    /// `MAX_ENTRIES_PER_PAGE`), которые реально изменились с прошлого
    /// commit'а и должны быть перешифрованы заново при следующем.
    dirty_pages: HashSet<usize>,
    /// Номера страниц File Table, которые не удалось расшифровать при
    /// последней загрузке (unlock/reload) — их записи безвозвратно
    /// потеряны, но остальная File Table по-прежнему доступна (ROADMAP.md,
    /// "Восстановление при частичном повреждении File Table"). Пусто в
    /// нормальном случае. Чисто информационное поле — само по себе ни на
    /// что не влияет, кроме `lost_file_table_pages()`.
    lost_file_table_pages: Vec<usize>,
    /// Эта сессия своими действиями осиротила хотя бы один блок данных
    /// (окончательное удаление файла, перезапись содержимого, перегенерация
    /// миниатюры) с прошлого `compact()`. По прямой просьбе пользователя —
    /// "после удаления файла база должна становиться легче" — `close()`
    /// автоматически запускает `compact()` вместо обычного `commit()`,
    /// когда этот флаг взведён, и не запускает (обычный дешёвый commit),
    /// если ничего не осиротело — иначе каждый выход из сессии, даже без
    /// единого удаления, стоил бы как полная перезапись контейнера.
    orphans_created: bool,
}

impl Container {
    pub fn create(
        path: &str,
        admin_username: &str,
        admin_password: &str,
    ) -> Result<(Self, RecoveryPhrase)> {
        if Path::new(path).exists() {
            return Err(CoveError::AlreadyExists);
        }

        let dek = keys::Dek::generate();
        let params = kdf::KdfParams::default();

        let admin_salt = random_salt();
        let admin_kek = kdf::derive_kek(admin_password.as_bytes(), &admin_salt, params)?;
        let admin_slot = Keyslot {
            slot_type: SlotType::User,
            username: admin_username.to_string(),
            role: Role::Admin,
            kdf_salt: admin_salt,
            kdf_params: params,
            wrapped_dek: keys::wrap_dek(&dek, &admin_kek)?,
        };

        let (recovery_slot, recovery_phrase) = create_recovery_slot(&dek, params)?;

        let keyslots_bytes =
            keyslots::serialize_region(&[admin_slot.clone(), recovery_slot.clone()])?;
        let mut initial_keyslots: Vec<Option<Keyslot>> = vec![None; keyslots::CAPACITY];
        initial_keyslots[0] = Some(admin_slot);
        initial_keyslots[1] = Some(recovery_slot);

        let keyslots_offset = header::HEADER_LEN as u64;
        let keyslots_len = keyslots_bytes.len() as u64;
        let commit_a_offset = keyslots_offset + keyslots_len;
        let commit_b_offset = commit_a_offset + commit::COMMIT_POINTER_LEN as u64;
        let region_start = commit_b_offset + commit::COMMIT_POINTER_LEN as u64;

        let free_map_bytes = free_map::encode(&[], &dek);
        let free_map_offset = region_start;
        let file_table_bytes = file_table::encode_file_table(&[], &dek);
        let file_table_offset = free_map_offset + free_map_bytes.len() as u64;

        let initial_log = vec![LoginLogEntry {
            username: admin_username.to_string(),
            timestamp: now_unix(),
            success: true,
        }];
        let login_log_bytes = login_log::encode(&initial_log, &dek);
        let login_log_offset = file_table_offset + file_table_bytes.len() as u64;

        let superblock_offset = login_log_offset + login_log_bytes.len() as u64;

        let sb = Superblock {
            version_counter: 1,
            file_table_offset,
            file_table_len: file_table_bytes.len() as u64,
            file_table_backup_offset: file_table_offset, // первая версия — резервной ещё нет
            search_index_offset: 0,
            search_index_len: 0,
            free_block_map_offset: free_map_offset,
            free_block_map_len: free_map_bytes.len() as u64,
            login_log_offset,
            login_log_len: login_log_bytes.len() as u64,
        };
        let sb_blob = sb.encode(&dek);

        let hdr = Header {
            format_version: FORMAT_VERSION,
            container_uuid: random_uuid(),
            created_at: now_unix(),
            block_size: DEFAULT_BLOCK_SIZE,
            keyslots_offset,
            keyslots_len,
            commit_a_offset,
            commit_b_offset,
        };

        let pointer = CommitPointer {
            version_counter: 1,
            superblock_offset,
            superblock_checksum: *blake3::hash(&sb_blob).as_bytes(),
        };

        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .read(true)
            .open(path)?;
        file.write_all(&hdr.serialize())?;
        file.write_all(&keyslots_bytes)?;
        file.write_all(&pointer.serialize())?; // slot A — активный, версия 1
        file.write_all(&[0u8; commit::COMMIT_POINTER_LEN])?; // slot B — пуст
        file.write_all(&free_map_bytes)?;
        file.write_all(&file_table_bytes)?;
        file.write_all(&login_log_bytes)?;
        file.write_all(&sb_blob)?;
        file.sync_all()?;

        Ok((
            Container {
                path: PathBuf::from(path),
                header: hdr,
                session: Session { dek },
                superblock: sb,
                file_table: Vec::new(),
                free_blocks: Vec::new(),
                keyslots: initial_keyslots,
                login_log: initial_log,
                current_username: admin_username.to_string(),
                current_role: Role::Admin,
                next_file_id: 1, // 0 зарезервирован под ROOT_FOLDER_ID
                dirty: false,
                file_table_page_cache: Vec::new(),
                dirty_pages: HashSet::new(),
                lost_file_table_pages: Vec::new(),
                orphans_created: false,
            },
            recovery_phrase,
        ))
    }

    fn require_admin(&self) -> Result<()> {
        if self.current_role == Role::Admin {
            Ok(())
        } else {
            Err(CoveError::PermissionDenied)
        }
    }

    fn write_keyslot_at(&self, index: usize, bytes: &[u8; keyslots::SLOT_LEN]) -> Result<()> {
        let mut file = OpenOptions::new().write(true).open(&self.path)?;
        let offset = self.header.keyslots_offset + (index * keyslots::SLOT_LEN) as u64;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    }

    /// Точечная перезапись ОДНОГО слота на диске — остальные 15 слотов не
    /// трогаются независимо от того, в какой момент случится сбой
    /// (FORMAT.md §3: слоты фиксированного размера, адресуются по индексу).
    pub fn add_user(&mut self, username: &str, password: &str, role: Role) -> Result<()> {
        self.require_admin()?;
        if username.is_empty() {
            return Err(CoveError::FormatError {
                detail: "username must not be empty".into(),
            });
        }
        let already_taken = self.keyslots.iter().flatten().any(|s| {
            s.slot_type == SlotType::User && s.username == username
        });
        if already_taken {
            return Err(CoveError::AlreadyExists);
        }
        let index = self
            .keyslots
            .iter()
            .position(|s| s.is_none())
            .ok_or_else(|| CoveError::FormatError {
                detail: "keyslot capacity exceeded".into(),
            })?;

        let salt = random_salt();
        let params = kdf::KdfParams::default();
        let kek = kdf::derive_kek(password.as_bytes(), &salt, params)?;
        let slot = Keyslot {
            slot_type: SlotType::User,
            username: username.to_string(),
            role,
            kdf_salt: salt,
            kdf_params: params,
            wrapped_dek: keys::wrap_dek(&self.session.dek, &kek)?,
        };

        let bytes = keyslots::serialize_slot(&slot)?;
        self.write_keyslot_at(index, &bytes)?;
        self.keyslots[index] = Some(slot);
        Ok(())
    }

    /// Список активных пользователей (без recovery-слота) — Фаза 12. До
    /// этого метода перечислить пользователей уже разблокированного
    /// контейнера было нечем: `remove_user`/`add_user` были, а посмотреть,
    /// кто вообще есть и с какой ролью, — нет.
    pub fn list_users(&self) -> Vec<(String, Role)> {
        self.keyslots
            .iter()
            .flatten()
            .filter(|s| s.slot_type == SlotType::User)
            .map(|s| (s.username.clone(), s.role))
            .collect()
    }

    pub fn remove_user(&mut self, username: &str) -> Result<()> {
        self.require_admin()?;
        let index = self
            .keyslots
            .iter()
            .position(|s| {
                s.as_ref()
                    .is_some_and(|s| s.slot_type == SlotType::User && s.username == username)
            })
            .ok_or(CoveError::NotFound)?;

        let slot = self.keyslots[index].as_ref().unwrap();
        if slot.role == Role::Admin {
            let admin_count = self
                .keyslots
                .iter()
                .flatten()
                .filter(|s| s.slot_type == SlotType::User && s.role == Role::Admin)
                .count();
            // Нельзя остаться без единственного администратора — иначе
            // единственный путь внутрь контейнера — recovery-фраза.
            if admin_count <= 1 {
                return Err(CoveError::PermissionDenied);
            }
        }

        self.write_keyslot_at(index, &keyslots::EMPTY_SLOT)?;
        self.keyslots[index] = None;
        Ok(())
    }

    /// "Изменить" из ROADMAP.md Фазы 12 — меняет роль существующего
    /// пользователя. Тот же инвариант, что у `remove_user`: нельзя разжаловать
    /// единственного администратора (иначе некому будет управлять
    /// пользователями, а recovery-фраза — не замена повседневному входу).
    pub fn set_user_role(&mut self, username: &str, role: Role) -> Result<()> {
        self.require_admin()?;
        let index = self
            .keyslots
            .iter()
            .position(|s| {
                s.as_ref()
                    .is_some_and(|s| s.slot_type == SlotType::User && s.username == username)
            })
            .ok_or(CoveError::NotFound)?;

        let slot = self.keyslots[index].as_ref().unwrap();
        if slot.role == Role::Admin && role != Role::Admin {
            let admin_count = self
                .keyslots
                .iter()
                .flatten()
                .filter(|s| s.slot_type == SlotType::User && s.role == Role::Admin)
                .count();
            if admin_count <= 1 {
                return Err(CoveError::PermissionDenied);
            }
        }

        let mut updated = slot.clone();
        updated.role = role;
        let bytes = keyslots::serialize_slot(&updated)?;
        self.write_keyslot_at(index, &bytes)?;
        self.keyslots[index] = Some(updated);
        Ok(())
    }

    pub fn change_password(&mut self, username: &str, old: &str, new: &str) -> Result<()> {
        let index = self
            .keyslots
            .iter()
            .position(|s| {
                s.as_ref()
                    .is_some_and(|s| s.slot_type == SlotType::User && s.username == username)
            })
            .ok_or(CoveError::AuthFailed)?;

        let slot = self.keyslots[index].as_ref().unwrap();
        let old_kek = kdf::derive_kek(old.as_bytes(), &slot.kdf_salt, slot.kdf_params)?;
        let unwrapped = keys::unwrap_dek(&slot.wrapped_dek, &old_kek)?;
        // Все keyslot'ы оборачивают один и тот же DEK контейнера (FORMAT.md
        // §0.2) — если unwrap успешен, иного значения тут просто быть не
        // может; это защитная проверка инварианта, а не основная аутентификация
        // (её уже выполнил AEAD внутри unwrap_dek выше).
        if unwrapped.as_bytes() != self.session.dek.as_bytes() {
            return Err(CoveError::AuthFailed);
        }

        let new_salt = random_salt();
        let new_kek = kdf::derive_kek(new.as_bytes(), &new_salt, slot.kdf_params)?;
        let mut updated = slot.clone();
        updated.kdf_salt = new_salt;
        updated.wrapped_dek = keys::wrap_dek(&self.session.dek, &new_kek)?;

        let bytes = keyslots::serialize_slot(&updated)?;
        self.write_keyslot_at(index, &bytes)?;
        self.keyslots[index] = Some(updated);
        Ok(())
    }

    /// Не включает записи в корзине и internal-записи (миниатюры и прочая
    /// служебная требуха — FORMAT.md §5: "не показываются в библиотеке").
    /// "Корзина" — та же логика, что виртуальный раздел в будущей Фазе 10,
    /// но реализована уже сейчас как отдельный метод `list_trash`, а не
    /// полноценная система виртуальных разделов.
    pub fn list_dir(&self, folder_id: FileId) -> Result<Vec<FileEntry>> {
        Ok(self
            .file_table
            .iter()
            .filter(|e| e.parent_id == folder_id && !e.flags.trashed && !e.flags.internal)
            .cloned()
            .collect())
    }

    pub fn list_trash(&self) -> Vec<FileEntry> {
        self.file_table
            .iter()
            .filter(|e| e.flags.trashed)
            .cloned()
            .collect()
    }

    fn require_writable(&self) -> Result<()> {
        if self.current_role == Role::ReadOnly {
            Err(CoveError::PermissionDenied)
        } else {
            Ok(())
        }
    }

    /// Помечает страницу, содержащую позицию `pos` в `file_table`, как
    /// изменившуюся с прошлого commit'а — она будет перешифрована заново
    /// вместо переиспользования из кэша (`encode_file_table_incremental`).
    fn mark_page_dirty_for_position(&mut self, pos: usize) {
        self.dirty_pages.insert(pos / file_table::MAX_ENTRIES_PER_PAGE);
    }

    /// `retain()`-подобное удаление сдвигает позиции ВСЕХ элементов после
    /// точки удаления — точный пересчёт, какие страницы затронуты, легко
    /// сделать с ошибкой на единицу. Такие операции (окончательное удаление
    /// из корзины, чистка миниатюр при перезаписи содержимого) на порядок
    /// реже точечных правок вроде импорта одного файла — цена
    /// консервативного "перешифровать всё" тут незначительна, а
    /// корректность гарантированная.
    fn mark_all_pages_dirty(&mut self) {
        let entry_count = self.file_table.len();
        let page_count = if entry_count == 0 {
            1
        } else {
            entry_count.div_ceil(file_table::MAX_ENTRIES_PER_PAGE)
        };
        self.dirty_pages.extend(0..page_count);
    }

    fn next_file_id(&mut self) -> FileId {
        let id = self.next_file_id;
        self.next_file_id += 1;
        id
    }

    fn folder_exists(&self, folder_id: FileId) -> bool {
        folder_id == ROOT_FOLDER_ID
            || self
                .file_table
                .iter()
                .any(|e| e.file_id == folder_id && e.flags.is_folder)
    }

    /// Является ли `candidate` тем же узлом, что и `ancestor`, либо его
    /// потомком (по цепочке `parent_id` вверх до корня). Используется и для
    /// поиска "внутри папки" (Фаза 9), и для защиты `move_file` от
    /// зацикливания дерева (нельзя переместить папку в саму себя/потомка).
    /// Цикл в файловом дереве в принципе не должен возникать, но предел
    /// итераций — защита на случай повреждённых данных, а не штатный путь.
    fn is_same_or_descendant(&self, candidate: FileId, ancestor: FileId) -> bool {
        let mut current = candidate;
        for _ in 0..=self.file_table.len() {
            if current == ancestor {
                return true;
            }
            if current == ROOT_FOLDER_ID {
                return false;
            }
            match self.file_table.iter().find(|e| e.file_id == current) {
                Some(entry) => current = entry.parent_id,
                None => return false,
            }
        }
        false
    }

    /// Читает и расшифровывает один блок данных по его byte-offset'у в
    /// файле-контейнере. Сначала читается фиксированный заголовок (в нём —
    /// длина plaintext), затем ровно столько шифртекста, сколько нужно —
    /// без знания длины блока заранее (FORMAT.md §6).
    /// `expected_file_id`/`expected_block_index` — координаты, которым
    /// вызывающая сторона доверяет (из File Table и позиции в
    /// `block_list`), используются для проверки AAD в `decode_block` —
    /// см. `format::data_blocks` и docs/SECURITY_SELF_REVIEW.md
    /// (защита от подмены/перестановки блоков между файлами).
    fn read_block_at(
        &self,
        file: &mut File,
        offset: u64,
        expected_file_id: FileId,
        expected_block_index: u32,
    ) -> Result<Vec<u8>> {
        file.seek(SeekFrom::Start(offset))?;
        let mut header_buf = [0u8; data_blocks::HEADER_LEN];
        file.read_exact(&mut header_buf)?;
        let header = data_blocks::parse_header(&header_buf);

        // block header (включая plaintext_len) лежит перед AEAD-шифртекстом
        // и им не защищён — тот, у кого есть запись на диск, но нет пароля,
        // может подменить только это поле, не трогая ciphertext/tag.
        // Легитимный блок никогда не превышает block_size (Container всегда
        // режет данные на чанки этого размера при записи) — сверяем ДО
        // аллокации, иначе испорченный файл заставит честного пользователя
        // при чтении своих же файлов попытаться выделить до 4ГБ по одному
        // подделанному полю (Фаза 17, тот же класс бага что и с
        // header.keyslots_len в LockedContainer::open).
        if header.plaintext_len as u64 > self.header.block_size as u64 {
            return Err(CoveError::FormatError {
                detail: "data block plaintext_len exceeds block_size — corrupted container".into(),
            });
        }
        let mut rest = vec![0u8; header.plaintext_len as usize + crate::crypto::aead::TAG_LEN];
        file.read_exact(&mut rest)?;

        let mut full = Vec::with_capacity(header_buf.len() + rest.len());
        full.extend_from_slice(&header_buf);
        full.extend_from_slice(&rest);
        data_blocks::decode_block(&full, &self.session.dek, expected_file_id, expected_block_index)
    }

    /// Общая логика чанкирования+шифрования+записи, используемая и
    /// `import_file` (новый файл), и `replace_file_content` (перезапись
    /// содержимого существующего). Блоки дописываются в конец файла-
    /// контейнера — переиспользование места старых блоков не в этой фазе.
    fn write_blocks_from(&self, file_id: FileId, src_path: &str) -> Result<(Vec<u64>, u64, [u8; 32])> {
        let mut src = File::open(src_path)?;
        self.write_blocks_from_reader(file_id, &mut src)
    }

    /// То же самое, но источник — байты уже в памяти (используется для
    /// миниатюр: генерация происходит в GUI-слое через уже decoded картинку,
    /// результат нигде не касается диска в открытом виде — ROADMAP.md Фаза 8).
    fn write_blocks_from_bytes(&self, file_id: FileId, data: &[u8]) -> Result<(Vec<u64>, u64, [u8; 32])> {
        let mut cursor = std::io::Cursor::new(data);
        self.write_blocks_from_reader(file_id, &mut cursor)
    }

    fn write_blocks_from_reader(
        &self,
        file_id: FileId,
        src: &mut impl Read,
    ) -> Result<(Vec<u64>, u64, [u8; 32])> {
        let mut container_file = OpenOptions::new().read(true).write(true).open(&self.path)?;

        let block_size = self.header.block_size as usize;
        let mut buf = vec![0u8; block_size];
        let mut block_list = Vec::new();
        let mut block_index: u32 = 0;
        let mut hasher = blake3::Hasher::new();
        let mut total_size: u64 = 0;

        loop {
            let n = read_fill(src, &mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            total_size += n as u64;

            let encoded = data_blocks::encode_block(file_id, block_index, &buf[..n], &self.session.dek);
            let offset = container_file.seek(SeekFrom::End(0))?;
            container_file.write_all(&encoded)?;
            block_list.push(offset);
            block_index += 1;

            if n < block_size {
                break;
            }
        }
        // Без fsync здесь: блоки без записи в File Table всё равно не
        // видны и не commit'нуты (File Table пишется на диск только в
        // close(), см. doc-комментарий там) — fsync на каждый импортируемый
        // файл не даёт никакой дополнительной гарантии сохранности, а
        // только дорого стоит при массовом импорте (Фаза 15: 100k мелких
        // файлов — 39s импорта, из них почти всё время в этом fsync).
        // Реальная точка durability для данных блоков — fsync в close().

        Ok((block_list, total_size, *hasher.finalize().as_bytes()))
    }

    fn remove_thumbnail_of(&mut self, file_id: FileId) {
        let before = self.file_table.len();
        self.file_table
            .retain(|e| !(e.flags.internal && e.thumbnail_of == Some(file_id)));
        if self.file_table.len() != before {
            self.mark_all_pages_dirty();
            // Удалённая internal-запись миниатюры уносит с собой свой
            // собственный block_list — те блоки данных стали орфанами.
            self.orphans_created = true;
        }
    }

    /// Возвращает `file_id` уже сгенерированной миниатюры, если она есть —
    /// вызывающая сторона (GUI) сверяется с этим перед тем как заново decode+
    /// scale исходное изображение.
    pub fn find_thumbnail(&self, file_id: FileId) -> Option<FileId> {
        self.file_table
            .iter()
            .find(|e| e.flags.internal && e.thumbnail_of == Some(file_id))
            .map(|e| e.file_id)
    }

    /// Сохраняет уже сгенерированные байты миниатюры (decode+resize — забота
    /// вызывающей стороны, см. комментарий у `write_blocks_from_bytes`) как
    /// internal-запись File Table, привязанную к `file_id` через
    /// `thumbnail_of`. Повторный вызов для того же файла перезаписывает
    /// существующую запись, а не плодит дубликаты.
    pub fn thumbnail(&mut self, file_id: FileId, thumbnail_data: &[u8]) -> Result<FileId> {
        self.require_writable()?;
        if !self.file_table.iter().any(|e| e.file_id == file_id) {
            return Err(CoveError::NotFound);
        }

        let thumb_id = self.find_thumbnail(file_id).unwrap_or_else(|| self.next_file_id());
        let (block_list, size, content_hash) = self.write_blocks_from_bytes(thumb_id, thumbnail_data)?;
        let now = now_unix();

        if let Some(pos) = self.file_table.iter().position(|e| e.file_id == thumb_id) {
            let entry = &mut self.file_table[pos];
            entry.block_list = block_list;
            entry.size = size;
            entry.content_hash = content_hash;
            entry.modified_at = now;
            self.mark_page_dirty_for_position(pos);
        } else {
            self.file_table.push(FileEntry {
                file_id: thumb_id,
                parent_id: ROOT_FOLDER_ID, // не важно — internal-записи не участвуют в list_dir
                name: format!("__thumbnail_{file_id}__"),
                size,
                created_at: now,
                modified_at: now,
                mime_hint: Some("image/png".to_string()),
                content_hash,
                block_list,
                flags: file_table::FileFlags {
                    internal: true,
                    ..Default::default()
                },
                thumbnail_of: Some(file_id),
                folder_category: None,
            });
            self.mark_page_dirty_for_position(self.file_table.len() - 1);
        }
        Ok(thumb_id)
    }

    pub fn import_file(&mut self, src_path: &str, parent_id: FileId) -> Result<FileId> {
        self.require_writable()?;
        if !self.folder_exists(parent_id) {
            return Err(CoveError::NotFound);
        }
        let name = Path::new(src_path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .ok_or_else(|| CoveError::FormatError {
                detail: "source path has no file name".into(),
            })?;

        let file_id = self.next_file_id();
        let (block_list, size, content_hash) = self.write_blocks_from(file_id, src_path)?;

        let now = now_unix();
        self.file_table.push(FileEntry {
            file_id,
            parent_id,
            name,
            size,
            created_at: now,
            modified_at: now,
            mime_hint: guess_mime(src_path),
            content_hash,
            block_list,
            flags: file_table::FileFlags::default(),
            thumbnail_of: None,
            folder_category: None,
        });
        self.mark_page_dirty_for_position(self.file_table.len() - 1);
        self.dirty = true;
        Ok(file_id)
    }

    /// То же самое, что `import_file`, но источник — байты уже в памяти, а
    /// не путь к локальному файлу на диске. Нужен Web-бэкенду (Фаза 13):
    /// файл приходит через HTTP multipart upload, серверу просто нечем было
    /// бы взять "путь на диске" для содержимого, которое browser прислал
    /// напрямую в теле запроса.
    pub fn import_file_from_bytes(
        &mut self,
        name: &str,
        parent_id: FileId,
        data: &[u8],
    ) -> Result<FileId> {
        self.require_writable()?;
        if name.is_empty() {
            return Err(CoveError::FormatError {
                detail: "file name must not be empty".into(),
            });
        }
        if !self.folder_exists(parent_id) {
            return Err(CoveError::NotFound);
        }

        let file_id = self.next_file_id();
        let (block_list, size, content_hash) = self.write_blocks_from_bytes(file_id, data)?;

        let now = now_unix();
        self.file_table.push(FileEntry {
            file_id,
            parent_id,
            name: name.to_string(),
            size,
            created_at: now,
            modified_at: now,
            mime_hint: guess_mime(name),
            content_hash,
            block_list,
            flags: file_table::FileFlags::default(),
            thumbnail_of: None,
            folder_category: None,
        });
        self.mark_page_dirty_for_position(self.file_table.len() - 1);
        self.dirty = true;
        Ok(file_id)
    }

    /// Перезаписывает содержимое уже существующего файла (например, после
    /// редактирования во внешнем приложении — ROADMAP.md Фаза 6). Старые
    /// блоки становятся орфанами (см. комментарий у `write_blocks_from`),
    /// `file_id`/имя/родитель/флаги не меняются.
    pub fn replace_file_content(&mut self, file_id: FileId, src_path: &str) -> Result<()> {
        self.require_writable()?;
        if !self.file_table.iter().any(|e| e.file_id == file_id && !e.flags.is_folder) {
            return Err(CoveError::NotFound);
        }
        let (block_list, size, content_hash) = self.write_blocks_from(file_id, src_path)?;
        let pos = self
            .file_table
            .iter()
            .position(|e| e.file_id == file_id)
            .unwrap();
        let entry = &mut self.file_table[pos];
        entry.block_list = block_list;
        entry.size = size;
        entry.content_hash = content_hash;
        entry.modified_at = now_unix();
        self.mark_page_dirty_for_position(pos);
        // Старые блоки этой записи только что заменены новыми (см.
        // doc-комментарий метода выше) — они больше ни на что не ссылаются.
        self.orphans_created = true;
        // Содержимое изменилось — старая миниатюра больше не соответствует
        // файлу; следующий вызов thumbnail() честно перегенерирует её
        // (ROADMAP.md Фаза 8: "автообновление").
        self.remove_thumbnail_of(file_id);
        self.dirty = true;
        Ok(())
    }

    pub fn export_file(&self, file_id: FileId, dest_path: &str) -> Result<()> {
        let entry = self
            .file_table
            .iter()
            .find(|e| e.file_id == file_id && !e.flags.is_folder)
            .ok_or(CoveError::NotFound)?;

        let mut container_file = File::open(&self.path)?;
        let mut out = File::create(dest_path)?;
        for (block_index, &offset) in entry.block_list.iter().enumerate() {
            let plaintext =
                self.read_block_at(&mut container_file, offset, entry.file_id, block_index as u32)?;
            out.write_all(&plaintext)?;
        }
        out.sync_all()?;
        Ok(())
    }

    /// `category` — категория вкладки (`"image"`/`"video"`/`"document"`/…),
    /// в которой пользователь создал папку, или `None` для "Библиотеки"
    /// (см. `FileEntry::folder_category`). Привязывается один раз при
    /// создании, дальше не пересчитывается.
    pub fn create_folder(
        &mut self,
        name: &str,
        parent_id: FileId,
        category: Option<&str>,
    ) -> Result<FileId> {
        self.require_writable()?;
        if name.is_empty() {
            return Err(CoveError::FormatError {
                detail: "folder name must not be empty".into(),
            });
        }
        if !self.folder_exists(parent_id) {
            return Err(CoveError::NotFound);
        }

        let file_id = self.next_file_id();
        let now = now_unix();
        self.file_table.push(FileEntry {
            file_id,
            parent_id,
            name: name.to_string(),
            size: 0,
            created_at: now,
            modified_at: now,
            mime_hint: None,
            content_hash: [0u8; 32],
            block_list: Vec::new(),
            flags: file_table::FileFlags {
                is_folder: true,
                ..Default::default()
            },
            thumbnail_of: None,
            folder_category: category.map(|c| c.to_string()),
        });
        self.mark_page_dirty_for_position(self.file_table.len() - 1);
        self.dirty = true;
        Ok(file_id)
    }

    /// Первый вызов на нетронутой записи — перемещение в корзину
    /// (восстановимо). Повторный вызов на уже находящейся в корзине записи —
    /// окончательное удаление: просто снимается ссылка из File Table, сами
    /// блоки остаются на диске как орфаны (они зашифрованы, поэтому это не
    /// утечка — просто место, которое вернёт компактификация в Фазе 15).
    /// Ровно так, как описано в ROADMAP.md Фазе 6.
    pub fn delete_file(&mut self, file_id: FileId) -> Result<()> {
        self.require_writable()?;
        let entry = self
            .file_table
            .iter()
            .find(|e| e.file_id == file_id)
            .ok_or(CoveError::NotFound)?;

        if entry.flags.trashed {
            self.file_table
                .retain(|e| e.file_id != file_id && !(e.flags.internal && e.thumbnail_of == Some(file_id)));
            self.mark_all_pages_dirty();
            // Окончательное удаление — записи (и их блоки данных, если это
            // не пустая папка) только что физически осиротели. Не пытаемся
            // точно определить, была ли у конкретной записи содержимое
            // (папка — нет, файл — почти всегда да) — за редким исключением
            // "удалили только пустые папки" это верно, а цена ложного
            // срабатывания — один занятие лишний compact() при выходе, не
            // потеря данных.
            self.orphans_created = true;
        } else {
            let pos = self.file_table.iter().position(|e| e.file_id == file_id).unwrap();
            let entry = &mut self.file_table[pos];
            entry.flags.trashed = true;
            entry.modified_at = now_unix();
            self.mark_page_dirty_for_position(pos);
        }
        self.dirty = true;
        Ok(())
    }

    pub fn restore_file(&mut self, file_id: FileId) -> Result<()> {
        self.require_writable()?;
        let pos = self
            .file_table
            .iter()
            .position(|e| e.file_id == file_id)
            .ok_or(CoveError::NotFound)?;
        let entry = &mut self.file_table[pos];
        entry.flags.trashed = false;
        entry.modified_at = now_unix();
        self.mark_page_dirty_for_position(pos);
        self.dirty = true;
        Ok(())
    }

    pub fn rename_file(&mut self, file_id: FileId, new_name: &str) -> Result<()> {
        self.require_writable()?;
        if new_name.is_empty() {
            return Err(CoveError::FormatError {
                detail: "name must not be empty".into(),
            });
        }
        let pos = self
            .file_table
            .iter()
            .position(|e| e.file_id == file_id)
            .ok_or(CoveError::NotFound)?;
        let entry = &mut self.file_table[pos];
        entry.name = new_name.to_string();
        entry.modified_at = now_unix();
        self.mark_page_dirty_for_position(pos);
        self.dirty = true;
        Ok(())
    }

    pub fn move_file(&mut self, file_id: FileId, new_parent: FileId) -> Result<()> {
        self.require_writable()?;
        if !self.folder_exists(new_parent) {
            return Err(CoveError::NotFound);
        }
        // Нельзя переместить папку в саму себя или в собственную подпапку —
        // иначе дерево зацикливается и list_dir/search уйдут в бесконечный обход.
        if self.is_same_or_descendant(new_parent, file_id) {
            return Err(CoveError::FormatError {
                detail: "cannot move a folder into itself or its own subfolder".into(),
            });
        }
        let pos = self
            .file_table
            .iter()
            .position(|e| e.file_id == file_id)
            .ok_or(CoveError::NotFound)?;
        let entry = &mut self.file_table[pos];
        entry.parent_id = new_parent;
        entry.modified_at = now_unix();
        self.mark_page_dirty_for_position(pos);
        self.dirty = true;
        Ok(())
    }

    /// Вместе с `read_at` — основа стриминга видео без расшифровки файла
    /// целиком (ARCHITECTURE.md §4). Реализовано уже здесь (не отложено до
    /// Фазы 7), потому что `import_file` нужно на чём-то честно проверять
    /// round-trip; Фаза 7 добавит вокруг этого просмотрщики в GUI.
    pub fn file_size(&self, file_id: FileId) -> Result<u64> {
        self.file_table
            .iter()
            .find(|e| e.file_id == file_id)
            .map(|e| e.size)
            .ok_or(CoveError::NotFound)
    }

    pub fn read_at(&self, file_id: FileId, offset: u64, len: u32) -> Result<Vec<u8>> {
        let entry = self
            .file_table
            .iter()
            .find(|e| e.file_id == file_id)
            .ok_or(CoveError::NotFound)?;
        if offset >= entry.size || len == 0 {
            return Ok(Vec::new());
        }

        let block_size = self.header.block_size as u64;
        let mut container_file = File::open(&self.path)?;
        let mut result = Vec::with_capacity(len as usize);

        let mut cursor = offset;
        let end = offset.saturating_add(len as u64).min(entry.size);
        while cursor < end {
            let block_idx = (cursor / block_size) as usize;
            let Some(&block_offset) = entry.block_list.get(block_idx) else {
                break;
            };
            let plaintext = self.read_block_at(
                &mut container_file,
                block_offset,
                entry.file_id,
                block_idx as u32,
            )?;
            let in_block_offset = (cursor % block_size) as usize;
            let take = plaintext
                .len()
                .saturating_sub(in_block_offset)
                .min((end - cursor) as usize);
            result.extend_from_slice(&plaintext[in_block_offset..in_block_offset + take]);
            cursor += take as u64;
        }
        Ok(result)
    }

    /// Обход resident `file_table` в памяти — почему это не "тот самый
    /// линейный скан", которого опасался FORMAT.md, см. doc-комментарий
    /// в search.rs. Корзина и internal-записи (миниатюры) в результаты
    /// не попадают — как и в list_dir/list_trash.
    pub fn search(&self, query: SearchQuery) -> Result<Vec<FileEntry>> {
        let name_needle = query.name_contains.as_ref().map(|s| s.to_lowercase());
        let ext_needle = query.extension.as_ref().map(|s| s.to_lowercase());

        Ok(self
            .file_table
            .iter()
            .filter(|e| !e.flags.trashed && !e.flags.internal)
            .filter(|e| {
                name_needle
                    .as_ref()
                    .is_none_or(|needle| e.name.to_lowercase().contains(needle.as_str()))
            })
            .filter(|e| {
                ext_needle
                    .as_ref()
                    .is_none_or(|needle| &extension_of(&e.name) == needle)
            })
            .filter(|e| {
                query
                    .category
                    .as_ref()
                    .is_none_or(|cat| categorize(&e.name) == cat)
            })
            .filter(|e| {
                query
                    .folder_id
                    .is_none_or(|folder_id| self.is_same_or_descendant(e.parent_id, folder_id))
            })
            .filter(|e| query.min_size.is_none_or(|min| e.size >= min))
            .filter(|e| query.max_size.is_none_or(|max| e.size <= max))
            .filter(|e| query.modified_after.is_none_or(|after| e.modified_at >= after))
            .filter(|e| query.modified_before.is_none_or(|before| e.modified_at <= before))
            .filter(|e| query.favorite.is_none_or(|fav| e.flags.favorite == fav))
            .cloned()
            .collect())
    }

    /// Раздел "Избранное" (ROADMAP.md Фаза 10) — до этого метода флаг
    /// `flags.favorite` в File Table некому было выставлять. Не трогает
    /// `modified_at` — это оргструктурная пометка, а не изменение
    /// содержимого, не должна двигать файл в "Недавние".
    pub fn set_favorite(&mut self, file_id: FileId, favorite: bool) -> Result<()> {
        self.require_writable()?;
        let pos = self
            .file_table
            .iter()
            .position(|e| e.file_id == file_id)
            .ok_or(CoveError::NotFound)?;
        self.file_table[pos].flags.favorite = favorite;
        self.mark_page_dirty_for_position(pos);
        self.dirty = true;
        Ok(())
    }

    /// История входов текущей сессии — от самой старой к самой новой
    /// (журнал входов, ROADMAP.md Фаза 4).
    pub fn login_history(&self) -> &[LoginLogEntry] {
        &self.login_log
    }

    /// Кем вошли в эту сессию — "recovery" при входе по recovery-фразе
    /// (RECOVERY_IDENTITY). Нужно GUI для отображения "вошли как X".
    pub fn current_username(&self) -> &str {
        &self.current_username
    }

    pub fn current_role(&self) -> Role {
        self.current_role
    }

    /// Commit: File Table/Free Map/журнал входов перекодируются целиком
    /// (постраничная экономия записи File Table — Фаза 6/15) и дописываются
    /// в конец файла, затем один атомарный переключатель Commit Pointer —
    /// FORMAT.md §6a. Keyslots в commit не участвуют — они пишутся точечно
    /// сразу в add_user/remove_user/change_password.
    ///
    /// В отличие от `close()` не потребляет `self` — можно вызывать сколько
    /// угодно раз за сессию (не только один раз перед выходом). Добавлено по
    /// прямому запросу пользователя: раньше импорт файла/новая папка и т.д.
    /// были видны только в памяти открывшей их сессии до её закрытия —
    /// вторая параллельно открытая сессия (Desktop + Web одновременно)
    /// читала пустой диск, пока первая не закрывалась. GUI каждой платформы
    /// зовёт `commit()` после каждого пользовательского действия (не после
    /// каждого файла в batch-импорте — полное перекодирование File Table на
    /// каждый файл в импорте из тысяч файлов было бы квадратичным по
    /// времени, тот же класс проблемы, что фаззинг нашёл в Фазе 17).
    pub fn commit(&mut self) -> Result<()> {
        let mut file = OpenOptions::new().read(true).write(true).open(&self.path)?;

        let (current_pointer, active_offset) =
            read_valid_commit_pointer(&mut file, &self.header)?;

        // Кто-то другой (другая одновременно открытая сессия того же
        // контейнера) уже закоммитил после того, как эта сессия последний
        // раз синхронизировалась (unlock() или прошлый commit()) — писать
        // поверх нельзя своим устаревшим File Table, это тихо стёрло бы
        // чужие изменения. Если у ЭТОЙ сессии нет реальных несохранённых
        // правок (`!self.dirty` — просто читала/держала сессию открытой),
        // безопаснее молча ничего не делать, чем поднимать ошибку на
        // ровном месте: единственное, чем она жертвует — своей записью в
        // login_log за этот вход. Если правки есть — отклоняем громко
        // (CoveError::Conflict), чтобы пользователь узнал, а не тихо
        // потерял свою же папку/файл.
        if current_pointer.version_counter != self.superblock.version_counter {
            return if self.dirty { Err(CoveError::Conflict) } else { Ok(()) };
        }

        let next_offset = if active_offset == self.header.commit_a_offset {
            self.header.commit_b_offset
        } else {
            self.header.commit_a_offset
        };
        let next_version = current_pointer.version_counter + 1;

        let end = file.seek(SeekFrom::End(0))?;

        let free_map_bytes = free_map::encode(&self.free_blocks, &self.session.dek);
        let free_map_offset = end;
        file.write_all(&free_map_bytes)?;

        let file_table_bytes = file_table::encode_file_table_incremental(
            &self.file_table,
            &self.session.dek,
            &mut self.file_table_page_cache,
            &self.dirty_pages,
        );
        let file_table_offset = free_map_offset + free_map_bytes.len() as u64;
        file.write_all(&file_table_bytes)?;

        let login_log_bytes = login_log::encode(&self.login_log, &self.session.dek);
        let login_log_offset = file_table_offset + file_table_bytes.len() as u64;
        file.write_all(&login_log_bytes)?;

        let sb = Superblock {
            version_counter: next_version,
            file_table_offset,
            file_table_len: file_table_bytes.len() as u64,
            file_table_backup_offset: self.superblock.file_table_offset, // предыдущая валидная версия
            search_index_offset: self.superblock.search_index_offset,
            search_index_len: self.superblock.search_index_len,
            free_block_map_offset: free_map_offset,
            free_block_map_len: free_map_bytes.len() as u64,
            login_log_offset,
            login_log_len: login_log_bytes.len() as u64,
        };
        let superblock_offset = login_log_offset + login_log_bytes.len() as u64;
        let sb_blob = sb.encode(&self.session.dek);
        file.write_all(&sb_blob)?;
        file.sync_all()?;

        let pointer = CommitPointer {
            version_counter: next_version,
            superblock_offset,
            superblock_checksum: *blake3::hash(&sb_blob).as_bytes(),
        };
        file.seek(SeekFrom::Start(next_offset))?;
        file.write_all(&pointer.serialize())?;
        file.sync_all()?;

        // Иначе следующий commit() в этой же сессии посчитал бы
        // file_table_backup_offset от уже устаревшего superblock — Copy,
        // дешёвая замена по значению.
        self.superblock = sb;
        self.dirty = false;
        self.dirty_pages.clear();

        Ok(())
    }

    /// Финальный commit перед освобождением контейнера — тонкая обёртка над
    /// `commit()`, оставлена под тем же именем/сигнатурой (потребляет
    /// `self`), чтобы не ломать существующих вызывающих на всех трёх
    /// платформах, которые уже вызывают `close()` при выходе/логауте.
    ///
    /// По прямой просьбе пользователя — "после удаления файла база должна
    /// становиться легче" — если за время этой сессии реально осиротели
    /// блоки данных (`orphans_created`, взводится `delete_file`/
    /// `replace_file_content`/перегенерацией миниатюры), `close()` сам
    /// запускает `compact()` вместо обычного `commit()`: она и коммитит
    /// текущее состояние, и физически ужимает файл. Если ничего не
    /// удалялось — обычный дешёвый `commit()`, не полная перезапись
    /// контейнера на каждый выход из сессии, даже пустой.
    pub fn close(mut self) -> Result<()> {
        if self.orphans_created {
            self.compact()?;
            Ok(())
        } else {
            self.commit()
        }
    }

    /// Перечитывает File Table/Free Map/журнал входов с диска, если там
    /// более новая версия, чем видела эта сессия — по прямому запросу
    /// пользователя: раньше изменения из другой сессии (например, загрузка
    /// файла через Web) были видны в уже открытой Desktop-сессии только
    /// после полного логаута/повторного входа, commit()/close() это никак
    /// не решали — они синхронизируют то, что сессия ЗАПИСЫВАЕТ на диск, а
    /// не то, что она ЧИТАЕТ из уже открытого состояния. DEK уже есть в
    /// памяти (сессия уже разблокирована), поэтому пароль не нужен — та же
    /// расшифровка регионов, что и в `unlock_slot()`, но без повторного
    /// KDF/keyslot-похода.
    ///
    /// `Ok(true)` — состояние обновилось, `Ok(false)` — на диске всё та же
    /// версия, перечитывать было нечего (дешёвая проверка: один короткий
    /// read самого commit pointer, не всего File Table). Если у ЭТОЙ сессии
    /// есть свои несохранённые правки (`dirty`), перечитывание отклоняется
    /// тем же `Conflict`, что и `commit()` — молча заменить чужим состоянием
    /// правки пользователя, которые он ещё не видел подтверждёнными, было
    /// бы так же нечестно, как молча их потерять при записи.
    pub fn reload(&mut self) -> Result<bool> {
        let mut file = File::open(&self.path)?;
        let (pointer, _active_offset) = read_valid_commit_pointer(&mut file, &self.header)?;
        if pointer.version_counter == self.superblock.version_counter {
            return Ok(false);
        }
        if self.dirty {
            return Err(CoveError::Conflict);
        }

        let mut sb_blob = [0u8; superblock::BLOB_LEN];
        file.seek(SeekFrom::Start(pointer.superblock_offset))?;
        file.read_exact(&mut sb_blob)?;
        let sb = Superblock::decode(&sb_blob, &self.session.dek)?;

        let table_load = read_file_table_with_recovery(&mut file, &sb, &self.session.dek)?;
        let free_blocks = read_free_map(&mut file, &sb, &self.session.dek)?;
        let login_log = read_login_log(&mut file, &sb, &self.session.dek)?;

        self.next_file_id = table_load
            .entries
            .iter()
            .map(|e| e.file_id)
            .max()
            .map(|m| m + 1)
            .unwrap_or(1);
        self.superblock = sb;
        self.file_table = table_load.entries;
        self.free_blocks = free_blocks;
        self.login_log = login_log;
        // Состояние на диске только что заменило наше целиком — старый кэш
        // страниц (и любые накопленные "грязные" пометки) относится к уже
        // неактуальной раскладке, начинаем с чистого листа.
        self.file_table_page_cache = table_load.page_cache;
        self.dirty_pages.clear();
        self.lost_file_table_pages = table_load.corrupted_pages;
        Ok(true)
    }

    /// Номера страниц File Table, которые не удалось расшифровать при
    /// последней загрузке (`unlock`/`reload`) — их содержимое безвозвратно
    /// потеряно, но остальная библиотека доступна как обычно (ROADMAP.md,
    /// "Восстановление при частичном повреждении File Table"). Пустой список
    /// в норме. Чисто информационный метод — ничего не чинит и не требует
    /// вызова, вызывающая сторона (GUI) может использовать его, чтобы честно
    /// предупредить пользователя, а не молча показать неполную библиотеку.
    pub fn lost_file_table_pages(&self) -> &[usize] {
        &self.lost_file_table_pages
    }

    /// Компактификация (ROADMAP.md, "Компактификация свободных блоков
    /// данных"): физически пересобирает файл-контейнер заново, оставляя
    /// только то, на что реально ссылается ТЕКУЩАЯ File Table в памяти этой
    /// сессии. Формат Cove — append-only для File Table/Free Map/Login
    /// Log/Superblock (каждый `commit()` дописывает новые версии в конец
    /// файла, старые остаются на диске) и для блоков данных (удалённые/
    /// перезаписанные файлы оставляют орфанов, FORMAT.md §6/§9) — файл
    /// только растёт. `compact()` — единственная операция, которая его
    /// физически уменьшает.
    ///
    /// Требует прав на запись (как и `delete_file`/`replace_file_content` —
    /// именно они и создают орфанов, которые эта операция убирает; отдельного
    /// admin-барьера тут по прямой просьбе пользователя нет — это уборка за
    /// собственными действиями пользователя, а не смена структуры контейнера
    /// на уровне пользователей/ролей, как `add_user`/`remove_user`). Дорогая
    /// операция (перечитывает и переписывает весь контейнер), поэтому не
    /// часть штатного commit() — вызывается либо явно, либо автоматически из
    /// `close()`, см. там же. Как и весь остальной Core, не имеет
    /// межпроцессной блокировки (ROADMAP.md Фаза 13, известное ограничение)
    /// — параллельная запись в контейнер с другой сессии во время compact()
    /// может быть потеряна.
    ///
    /// Возвращает число байт, на которое уменьшился файл (0, если сжимать
    /// было нечего). Пишет полностью новый файл рядом (`<path>.compact.tmp`)
    /// и атомарно переименовывает его поверх старого только после того, как
    /// новый файл целиком записан и fsync'нут — при любой ошибке в процессе
    /// исходный файл остаётся нетронутым и рабочим.
    pub fn compact(&mut self) -> Result<u64> {
        self.require_writable()?;

        let old_size = std::fs::metadata(&self.path)?.len();

        let tmp_path = {
            let file_name = self
                .path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("container")
                .to_string();
            self.path.with_file_name(format!("{file_name}.compact.tmp"))
        };
        if tmp_path.exists() {
            std::fs::remove_file(&tmp_path)?;
        }

        let mut old_file = File::open(&self.path)?;

        // Keyslots уже хранятся точечно на фиксированных offset'ах
        // (FORMAT.md §3) — копируем байты как есть, а не пересериализуем из
        // self.keyslots, чтобы не рисковать байтовым расхождением обёрнутых
        // ключей.
        let mut keyslots_bytes = vec![0u8; self.header.keyslots_len as usize];
        old_file.seek(SeekFrom::Start(self.header.keyslots_offset))?;
        old_file.read_exact(&mut keyslots_bytes)?;

        let mut new_file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .read(true)
            .open(&tmp_path)?;

        // Header/keyslots/commit-slots структурно идентичны исходнику —
        // capacity keyslot'ов фиксирован, offset'ы этого региона не меняются.
        new_file.write_all(&self.header.serialize())?;
        new_file.write_all(&keyslots_bytes)?;
        new_file.write_all(&[0u8; commit::COMMIT_POINTER_LEN])?; // slot A — заполним ниже
        new_file.write_all(&[0u8; commit::COMMIT_POINTER_LEN])?; // slot B — остаётся пустым, как при create()

        // Переносим блоки данных ТОЛЬКО живых записей (текущий file_table в
        // памяти — уже с учётом любых несохранённых правок этой сессии)
        // вербатим: ciphertext+tag не трогаем, меняется только offset —
        // безопасно, т.к. AAD блока привязан к (file_id, block_index), а не
        // к его положению в файле (см. data_blocks::block_aad).
        let mut new_entries = self.file_table.clone();
        for entry in new_entries.iter_mut() {
            if entry.block_list.is_empty() {
                continue; // папки и internal-записи без содержимого
            }
            let mut new_offsets = Vec::with_capacity(entry.block_list.len());
            for &old_offset in &entry.block_list {
                let new_offset =
                    copy_block_verbatim(&mut old_file, &mut new_file, old_offset, self.header.block_size)?;
                new_offsets.push(new_offset);
            }
            entry.block_list = new_offsets;
        }

        // Орфанов, которые могла бы отслеживать Free Map, после
        // компактификации по определению не осталось.
        let free_map_bytes = free_map::encode(&[], &self.session.dek);
        let free_map_offset = new_file.stream_position()?;
        new_file.write_all(&free_map_bytes)?;

        // Полная перекодировка File Table с нуля — свежий кэш страниц,
        // старый относился к уже неактуальной физической раскладке блоков.
        let mut fresh_cache = Vec::new();
        let page_count = if new_entries.is_empty() {
            1
        } else {
            new_entries.len().div_ceil(file_table::MAX_ENTRIES_PER_PAGE)
        };
        let all_dirty: HashSet<usize> = (0..page_count).collect();
        let file_table_bytes = file_table::encode_file_table_incremental(
            &new_entries,
            &self.session.dek,
            &mut fresh_cache,
            &all_dirty,
        );
        let file_table_offset = free_map_offset + free_map_bytes.len() as u64;
        new_file.write_all(&file_table_bytes)?;

        let login_log_bytes = login_log::encode(&self.login_log, &self.session.dek);
        let login_log_offset = file_table_offset + file_table_bytes.len() as u64;
        new_file.write_all(&login_log_bytes)?;

        let next_version = self.superblock.version_counter + 1;
        let sb = Superblock {
            version_counter: next_version,
            file_table_offset,
            file_table_len: file_table_bytes.len() as u64,
            // Компактификация — новая база; прежней истории для отката
            // больше физически не существует (мы её только что стёрли).
            file_table_backup_offset: file_table_offset,
            search_index_offset: 0,
            search_index_len: 0,
            free_block_map_offset: free_map_offset,
            free_block_map_len: free_map_bytes.len() as u64,
            login_log_offset,
            login_log_len: login_log_bytes.len() as u64,
        };
        let superblock_offset = login_log_offset + login_log_bytes.len() as u64;
        let sb_blob = sb.encode(&self.session.dek);
        new_file.write_all(&sb_blob)?;
        new_file.sync_all()?;

        let pointer = CommitPointer {
            version_counter: next_version,
            superblock_offset,
            superblock_checksum: *blake3::hash(&sb_blob).as_bytes(),
        };
        new_file.seek(SeekFrom::Start(self.header.commit_a_offset))?;
        new_file.write_all(&pointer.serialize())?;
        new_file.sync_all()?;

        drop(new_file);
        drop(old_file);
        std::fs::rename(&tmp_path, &self.path)?;

        self.superblock = sb;
        self.file_table = new_entries;
        self.free_blocks = Vec::new();
        self.file_table_page_cache = fresh_cache;
        self.dirty_pages.clear();
        self.lost_file_table_pages.clear();
        self.dirty = false;
        self.orphans_created = false;

        let new_size = std::fs::metadata(&self.path)?.len();
        Ok(old_size.saturating_sub(new_size))
    }
}

fn random_salt() -> [u8; kdf::SALT_LEN] {
    let mut salt = [0u8; kdf::SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}

fn random_uuid() -> [u8; 16] {
    let mut uuid = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut uuid);
    uuid
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// `Read::read()` не обязан заполнять буфер целиком за один вызов даже до
/// EOF — дочитываем, пока буфер не заполнится или не кончится источник.
fn read_fill(reader: &mut impl Read, buf: &mut [u8]) -> Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..])? {
            0 => break,
            n => total += n,
        }
    }
    Ok(total)
}

fn guess_mime(path: &str) -> Option<String> {
    let ext = Path::new(path).extension()?.to_str()?.to_lowercase();
    let mime = match ext.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "heif" | "heic" => "image/heif",
        "mp4" => "video/mp4",
        "mkv" => "video/x-matroska",
        "avi" => "video/x-msvideo",
        "mov" => "video/quicktime",
        "webm" => "video/webm",
        "pdf" => "application/pdf",
        "txt" => "text/plain",
        "md" => "text/markdown",
        "mp3" => "audio/mpeg",
        "flac" => "audio/flac",
        "aac" => "audio/aac",
        "ogg" => "audio/ogg",
        _ => return None,
    };
    Some(mime.to_string())
}

/// Расширение файла в нижнем регистре, без точки; пустая строка, если его нет.
fn extension_of(name: &str) -> String {
    Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase()
}

/// Категория для поиска "по типу" (Фаза 9) — та же классификация по
/// расширению, что и в desktop/app/file_kind.py на стороне GUI.
fn categorize(name: &str) -> &'static str {
    match extension_of(name).as_str() {
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "avif" | "heif" | "heic" | "bmp" | "tif"
        | "tiff" => "image",
        "mp4" | "mkv" | "avi" | "mov" | "webm" => "video",
        "mp3" | "flac" | "aac" | "ogg" => "audio",
        "pdf" | "txt" | "md" => "document",
        _ => "other",
    }
}

fn create_recovery_slot(dek: &keys::Dek, params: kdf::KdfParams) -> Result<(Keyslot, RecoveryPhrase)> {
    let mut entropy = [0u8; 16]; // 128 бит → 12-словная BIP39-фраза
    rand::rngs::OsRng.fill_bytes(&mut entropy);
    let mnemonic = bip39::Mnemonic::from_entropy(&entropy).map_err(|e| CoveError::FormatError {
        detail: format!("mnemonic generation failed: {e}"),
    })?;
    let phrase = mnemonic.to_string();

    let salt = random_salt();
    let kek = kdf::derive_kek(phrase.as_bytes(), &salt, params)?;
    let slot = Keyslot {
        slot_type: SlotType::Recovery,
        username: String::new(),
        role: Role::Admin,
        kdf_salt: salt,
        kdf_params: params,
        wrapped_dek: keys::wrap_dek(dek, &kek)?,
    };
    Ok((slot, RecoveryPhrase(phrase)))
}

/// Выбирает валидный Commit Pointer (FORMAT.md §6a/§8): сперва структурная
/// self-проверка без обращения к диску, затем сверка checksum'а с реально
/// лежащим на диске Superblock-блобом — до деривации ключа из пароля.
/// Возвращает указатель и offset слота, из которого он прочитан (нужно
/// `close()`, чтобы знать, в какой — противоположный — слот писать дальше).
fn read_valid_commit_pointer(file: &mut File, hdr: &Header) -> Result<(CommitPointer, u64)> {
    let mut read_slot = |offset: u64| -> Result<Option<CommitPointer>> {
        let mut buf = [0u8; commit::COMMIT_POINTER_LEN];
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut buf)?;
        if !CommitPointer::self_check(&buf) {
            return Ok(None);
        }
        let pointer = CommitPointer::parse(&buf);

        let mut sb_blob = vec![0u8; superblock::BLOB_LEN];
        file.seek(SeekFrom::Start(pointer.superblock_offset))?;
        if file.read_exact(&mut sb_blob).is_err() {
            return Ok(None);
        }
        if blake3::hash(&sb_blob).as_bytes()[..] != pointer.superblock_checksum {
            return Ok(None);
        }
        Ok(Some(pointer))
    };

    let a = read_slot(hdr.commit_a_offset)?;
    let b = read_slot(hdr.commit_b_offset)?;

    match (a, b) {
        (Some(a), Some(b)) if b.version_counter > a.version_counter => {
            Ok((b, hdr.commit_b_offset))
        }
        (Some(a), _) => Ok((a, hdr.commit_a_offset)),
        (None, Some(b)) => Ok((b, hdr.commit_b_offset)),
        (None, None) => Err(CoveError::FormatError {
            detail: "no valid commit pointer — container unopenable".into(),
        }),
    }
}

/// Читает и щадяще разбирает File Table основной (текущей) версии —
/// отдельные повреждённые страницы не мешают прочитать остальные (см.
/// `file_table::decode_file_table_lenient`). Если основной блоб не
/// разбирается вообще СТРУКТУРНО (не про отдельные страницы — framing
/// целиком нечитаем: усечённый файл, чужой формат и т.п.), последняя
/// попытка — `file_table_backup_offset`: предыдущая валидная версия File
/// Table, на которую указывает Superblock ещё с Фазы 2, но которую до сих
/// пор никто не читал (ROADMAP.md, "восстановление при частичном
/// повреждении File Table"). Это более грубый запасной вариант — теряются
/// ВСЕ изменения с предыдущего commit'а, а не только одна страница, — и
/// применяется только тогда, когда даже постраничное восстановление
/// невозможно.
fn read_file_table_with_recovery(
    file: &mut File,
    sb: &Superblock,
    dek: &keys::Dek,
) -> Result<file_table::LenientLoad> {
    let primary = read_file_table_lenient_at(file, sb.file_table_offset, sb.file_table_len, dek);
    match primary {
        Ok(load) => Ok(load),
        Err(primary_err) => {
            if sb.file_table_backup_offset == sb.file_table_offset {
                return Err(primary_err); // отдельной резервной версии ещё не было (первый commit)
            }
            // Superblock хранит только offset резервной версии, не её длину
            // (она была известна только в момент того commit'а, который уже
            // затёрт этим сбоем) — читаем с запасом до конца файла и
            // полагаемся на framing внутри блоба, чтобы понять, где он
            // реально заканчивается (split_page_slices не читает байт
            // больше, чем сама объявляет структура, лишний хвост в буфере
            // просто игнорируется).
            let file_len = file.seek(SeekFrom::End(0))?;
            if sb.file_table_backup_offset >= file_len {
                return Err(primary_err);
            }
            read_file_table_lenient_at(
                file,
                sb.file_table_backup_offset,
                file_len - sb.file_table_backup_offset,
                dek,
            )
        }
    }
}

fn read_file_table_lenient_at(
    file: &mut File,
    offset: u64,
    len: u64,
    dek: &keys::Dek,
) -> Result<file_table::LenientLoad> {
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; len as usize];
    file.read_exact(&mut buf)?;
    file_table::decode_file_table_lenient(&buf, dek)
}

fn read_free_map(file: &mut File, sb: &Superblock, dek: &keys::Dek) -> Result<Vec<u64>> {
    file.seek(SeekFrom::Start(sb.free_block_map_offset))?;
    let mut buf = vec![0u8; sb.free_block_map_len as usize];
    file.read_exact(&mut buf)?;
    free_map::decode(&buf, dek)
}

/// Копирует один блок данных (header + ciphertext + tag) с одного offset'а
/// на другой как есть, без расшифровки/повторного шифрования — используется
/// `Container::compact()`. Возвращает offset, по которому блок оказался в
/// `dst`. Та же проверка правдоподобия `plaintext_len`, что и в
/// `read_block_at` (Фаза 17) — компактификация тоже не должна слепо
/// доверять полю, лежащему перед AEAD-шифртекстом и им не защищённому.
fn copy_block_verbatim(src: &mut File, dst: &mut File, old_offset: u64, block_size: u32) -> Result<u64> {
    src.seek(SeekFrom::Start(old_offset))?;
    let mut header_buf = [0u8; data_blocks::HEADER_LEN];
    src.read_exact(&mut header_buf)?;
    let header = data_blocks::parse_header(&header_buf);
    if header.plaintext_len as u64 > block_size as u64 {
        return Err(CoveError::FormatError {
            detail: "data block plaintext_len exceeds block_size — corrupted container".into(),
        });
    }
    let mut rest = vec![0u8; header.plaintext_len as usize + crate::crypto::aead::TAG_LEN];
    src.read_exact(&mut rest)?;

    let new_offset = dst.stream_position()?;
    dst.write_all(&header_buf)?;
    dst.write_all(&rest)?;
    Ok(new_offset)
}

fn read_login_log(file: &mut File, sb: &Superblock, dek: &keys::Dek) -> Result<Vec<LoginLogEntry>> {
    file.seek(SeekFrom::Start(sb.login_log_offset))?;
    let mut buf = vec![0u8; sb.login_log_len as usize];
    file.read_exact(&mut buf)?;
    login_log::decode(&buf, dek)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn temp_container_path(tag: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!("cove_test_{tag}_{}_{n}.slr", std::process::id()))
    }

    fn write_temp_source_file(tag: &str, content: &[u8]) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!("cove_src_{tag}_{}_{n}.bin", std::process::id()));
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn create_close_reopen_unlock_roundtrip() {
        let path = temp_container_path("roundtrip");
        let path_str = path.to_str().unwrap();

        let (container, recovery) =
            Container::create(path_str, "admin", "correct horse battery staple").unwrap();
        assert!(!recovery.0.is_empty());
        container.close().unwrap();

        let locked = LockedContainer::open(path_str).unwrap();
        assert_eq!(locked.list_usernames(), vec!["admin".to_string()]);

        assert!(matches!(
            locked.unlock("admin", "wrong password"),
            Err(CoveError::AuthFailed)
        ));
        assert!(matches!(
            locked.unlock("nobody", "whatever"),
            Err(CoveError::AuthFailed)
        ));

        let unlocked = locked
            .unlock("admin", "correct horse battery staple")
            .unwrap();
        assert!(unlocked.list_dir(ROOT_FOLDER_ID).unwrap().is_empty());
        unlocked.close().unwrap();

        let locked2 = LockedContainer::open(path_str).unwrap();
        let via_recovery = locked2.unlock_with_recovery(&recovery.0).unwrap();
        assert!(via_recovery.list_dir(ROOT_FOLDER_ID).unwrap().is_empty());
        via_recovery.close().unwrap();

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn create_twice_fails() {
        let path = temp_container_path("twice");
        let path_str = path.to_str().unwrap();
        let (c, _) = Container::create(path_str, "admin", "pw12345678").unwrap();
        c.close().unwrap();

        assert!(matches!(
            Container::create(path_str, "admin", "pw12345678"),
            Err(CoveError::AlreadyExists)
        ));

        let _ = std::fs::remove_file(&path);
    }

    /// Фаза 17 — найдено при разборе парсера на предмет fuzzing-целей:
    /// header не аутентифицирован криптографически (только
    /// самосогласованный checksum, который злоумышленник волен
    /// пересчитать под любые значения полей), а `keyslots_len` раньше
    /// использовался напрямую как размер аллокации ДО того, как
    /// `keyslots::parse_region` успевал проверить длину — специально
    /// сфабрикованный файл с огромным `keyslots_len` валил бы процесс
    /// OOM-абортом ещё до ввода пароля. Теперь `open()` сверяет длину с
    /// единственно верной константой до аллокации.
    #[test]
    fn forged_huge_keyslots_len_rejected_not_oom() {
        let path = temp_container_path("forged_keyslots_len");
        let path_str = path.to_str().unwrap();
        let (c, _recovery) = Container::create(path_str, "admin", "pw12345678").unwrap();
        c.close().unwrap();

        let mut header_buf = [0u8; header::HEADER_LEN];
        {
            let mut f = File::open(path_str).unwrap();
            f.read_exact(&mut header_buf).unwrap();
        }
        let mut h = Header::parse(&header_buf).unwrap();
        h.keyslots_len = u64::MAX / 2; // заведомо неаллоцируемо, если довериться напрямую
        let forged = h.serialize(); // пересчитывает checksum — самосогласованный форгед header

        {
            let mut f = OpenOptions::new().write(true).open(path_str).unwrap();
            f.write_all(&forged).unwrap();
        }

        // Не паникует, не виснет на аллокации — честно возвращает ошибку.
        assert!(matches!(
            LockedContainer::open(path_str),
            Err(CoveError::FormatError { .. })
        ));

        let _ = std::fs::remove_file(&path);
    }

    /// Фаза 17 — блок-заголовок (включая `plaintext_len`) лежит перед AEAD-
    /// шифртекстом и им не защищён. Раньше `plaintext_len` использовался
    /// напрямую как размер аллокации до какой-либо проверки — честный
    /// пользователь, читающий свой же (испорченный кем-то с доступом на
    /// запись к файлу) контейнер, мог получить попытку выделить почти 4ГБ
    /// по одному подделанному полю. Теперь `read_block_at` сверяет
    /// `plaintext_len` с `block_size` до аллокации.
    #[test]
    fn forged_huge_block_plaintext_len_rejected_not_oom() {
        let path = temp_container_path("forged_block_len");
        let path_str = path.to_str().unwrap();
        let (mut c, _recovery) = Container::create(path_str, "admin", "pw12345678").unwrap();

        let src = write_temp_source_file("forged_block_len", b"hello world");
        let file_id = c.import_file(src.to_str().unwrap(), ROOT_FOLDER_ID).unwrap();
        let entry = c.list_dir(ROOT_FOLDER_ID).unwrap().into_iter().find(|e| e.file_id == file_id).unwrap();
        let block_offset = entry.block_list[0];
        c.close().unwrap();

        // plaintext_len — последние 4 байта заголовка блока (file_id(8) +
        // block_index(4) + nonce(24) + plaintext_len(4)).
        let plaintext_len_offset = block_offset + (data_blocks::HEADER_LEN as u64 - 4);
        {
            let mut f = OpenOptions::new().write(true).open(path_str).unwrap();
            f.seek(SeekFrom::Start(plaintext_len_offset)).unwrap();
            f.write_all(&u32::MAX.to_le_bytes()).unwrap();
        }

        let locked = LockedContainer::open(path_str).unwrap();
        let unlocked = locked.unlock("admin", "pw12345678").unwrap();
        // Не паникует, не пытается выделить ~4ГБ — честно возвращает ошибку.
        assert!(unlocked.read_at(file_id, 0, 11).is_err());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&src);
    }

    /// Найдено при саморевью крипто-части (docs/SECURITY_SELF_REVIEW.md):
    /// сквозной тест на реальном файле-контейнере, не только на уровне
    /// `format::data_blocks` — физически подменяет байты блока одного
    /// файла байтами блока другого (ровно то, что мог бы сделать
    /// атакующий с доступом на запись к `.slr`, но без пароля), как это
    /// уже делают предыдущие Фаза-17 тесты для других полей. До AAD-
    /// привязки `read_at()` на файл B тут вернул бы `Ok(содержимое файла
    /// A)` — тег AEAD оставался валиден, потому что ключ общий на весь
    /// контейнер, а nonce+ciphertext просто "переехали" на новое место
    /// целиком. Теперь обязан провалиться явной ошибкой.
    #[test]
    fn block_swapped_between_files_on_disk_rejected() {
        let path = temp_container_path("block_swap");
        let path_str = path.to_str().unwrap();
        let (mut c, _recovery) = Container::create(path_str, "admin", "pw12345678").unwrap();

        // Одинаковая ДЛИНА содержимого — важно, чтобы блоки А и Б занимали
        // на диске одинаковое число байт и подмену можно было сделать
        // простым copy_from_slice того же диапазона.
        let src_a = write_temp_source_file("swap_a", b"AAAAAAAAAAA");
        let src_b = write_temp_source_file("swap_b", b"BBBBBBBBBBB");
        let file_a = c.import_file(src_a.to_str().unwrap(), ROOT_FOLDER_ID).unwrap();
        let file_b = c.import_file(src_b.to_str().unwrap(), ROOT_FOLDER_ID).unwrap();
        let entries = c.list_dir(ROOT_FOLDER_ID).unwrap();
        let offset_a = entries.iter().find(|e| e.file_id == file_a).unwrap().block_list[0];
        let offset_b = entries.iter().find(|e| e.file_id == file_b).unwrap().block_list[0];
        c.close().unwrap();

        let block_len = data_blocks::total_len(11);
        {
            let mut f = OpenOptions::new().read(true).write(true).open(path_str).unwrap();
            f.seek(SeekFrom::Start(offset_a)).unwrap();
            let mut block_a_bytes = vec![0u8; block_len];
            f.read_exact(&mut block_a_bytes).unwrap();

            // Физически переносим байты блока А на позицию блока Б —
            // это и есть "атакующий с доступом на запись к файлу".
            f.seek(SeekFrom::Start(offset_b)).unwrap();
            f.write_all(&block_a_bytes).unwrap();
        }

        let locked = LockedContainer::open(path_str).unwrap();
        let unlocked = locked.unlock("admin", "pw12345678").unwrap();

        // Файл А по-прежнему корректно читается (его собственный блок не
        // трогали, только скопировали ИЗ него).
        assert_eq!(unlocked.read_at(file_a, 0, 11).unwrap(), b"AAAAAAAAAAA");
        // Файл Б обязан провалиться — НЕ вернуть подменённое "AAAAAAAAAAA".
        assert!(unlocked.read_at(file_b, 0, 11).is_err());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&src_a);
        let _ = std::fs::remove_file(&src_b);
    }

    #[test]
    fn wrong_recovery_phrase_fails() {
        let path = temp_container_path("recovery_wrong");
        let path_str = path.to_str().unwrap();
        let (c, _recovery) = Container::create(path_str, "admin", "pw12345678").unwrap();
        c.close().unwrap();

        let locked = LockedContainer::open(path_str).unwrap();
        assert!(matches!(
            locked.unlock_with_recovery("totally wrong phrase words here"),
            Err(CoveError::AuthFailed)
        ));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn add_user_login_persist_and_role_enforced() {
        let path = temp_container_path("add_user");
        let path_str = path.to_str().unwrap();
        let (mut c, _recovery) = Container::create(path_str, "admin", "adminpassword").unwrap();
        c.add_user("viewer", "viewerpassword", Role::ReadOnly).unwrap();
        c.close().unwrap();

        let locked = LockedContainer::open(path_str).unwrap();
        let mut usernames = locked.list_usernames();
        usernames.sort();
        assert_eq!(usernames, vec!["admin".to_string(), "viewer".to_string()]);

        // Новый пользователь реально может зайти и видит тот же (пустой) контейнер.
        let viewer = locked.unlock("viewer", "viewerpassword").unwrap();
        assert_eq!(viewer.current_role, Role::ReadOnly);
        assert!(viewer.list_dir(ROOT_FOLDER_ID).unwrap().is_empty());

        // Не-админ не может добавлять пользователей.
        let mut viewer = viewer;
        assert!(matches!(
            viewer.add_user("someone", "somepassword", Role::ReadOnly),
            Err(CoveError::PermissionDenied)
        ));
        viewer.close().unwrap();

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn cannot_remove_last_admin() {
        let path = temp_container_path("last_admin");
        let path_str = path.to_str().unwrap();
        let (mut c, _recovery) = Container::create(path_str, "admin", "adminpassword").unwrap();
        assert!(matches!(
            c.remove_user("admin"),
            Err(CoveError::PermissionDenied)
        ));
        c.close().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn remove_user_then_login_fails() {
        let path = temp_container_path("remove_user");
        let path_str = path.to_str().unwrap();
        let (mut c, _recovery) = Container::create(path_str, "admin", "adminpassword").unwrap();
        c.add_user("temp", "temppassword", Role::ReadWrite).unwrap();
        c.remove_user("temp").unwrap();
        c.close().unwrap();

        let locked = LockedContainer::open(path_str).unwrap();
        assert!(matches!(
            locked.unlock("temp", "temppassword"),
            Err(CoveError::AuthFailed)
        ));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn change_password_then_old_password_rejected() {
        let path = temp_container_path("change_pw");
        let path_str = path.to_str().unwrap();
        let (mut c, _recovery) = Container::create(path_str, "admin", "oldpassword").unwrap();
        c.change_password("admin", "oldpassword", "newpassword")
            .unwrap();
        c.close().unwrap();

        let locked = LockedContainer::open(path_str).unwrap();
        assert!(matches!(
            locked.unlock("admin", "oldpassword"),
            Err(CoveError::AuthFailed)
        ));
        let unlocked = locked.unlock("admin", "newpassword").unwrap();
        unlocked.close().unwrap();

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn login_history_records_successful_unlocks() {
        let path = temp_container_path("login_history");
        let path_str = path.to_str().unwrap();
        let (c, _recovery) = Container::create(path_str, "admin", "adminpassword").unwrap();
        assert_eq!(c.login_history().len(), 1); // создание контейнера = первый вход
        c.close().unwrap();

        let locked = LockedContainer::open(path_str).unwrap();
        let unlocked = locked.unlock("admin", "adminpassword").unwrap();
        assert_eq!(unlocked.login_history().len(), 2);
        unlocked.close().unwrap();

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn import_export_and_read_at_roundtrip() {
        let path = temp_container_path("import_small");
        let path_str = path.to_str().unwrap();
        let (mut c, _r) = Container::create(path_str, "admin", "adminpassword").unwrap();

        let content = b"hello cove, this is a small imported file".to_vec();
        let src = write_temp_source_file("small", &content);
        let file_id = c.import_file(src.to_str().unwrap(), ROOT_FOLDER_ID).unwrap();

        let listed = c.list_dir(ROOT_FOLDER_ID).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].file_id, file_id);
        assert_eq!(listed[0].size, content.len() as u64);
        assert_eq!(listed[0].mime_hint, None); // .bin — не в таблице guess_mime

        assert_eq!(c.file_size(file_id).unwrap(), content.len() as u64);
        assert_eq!(c.read_at(file_id, 0, content.len() as u32).unwrap(), content);
        assert_eq!(c.read_at(file_id, 6, 4).unwrap(), b"cove");

        let dest = std::env::temp_dir().join(format!("cove_export_{}.bin", std::process::id()));
        c.export_file(file_id, dest.to_str().unwrap()).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), content);

        c.close().unwrap();
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_file(&dest);
    }

    #[test]
    fn import_survives_close_reopen() {
        let path = temp_container_path("import_persist");
        let path_str = path.to_str().unwrap();
        let (mut c, _r) = Container::create(path_str, "admin", "adminpassword").unwrap();
        let content = b"persisted content".to_vec();
        let src = write_temp_source_file("persist", &content);
        let file_id = c.import_file(src.to_str().unwrap(), ROOT_FOLDER_ID).unwrap();
        c.close().unwrap();

        let locked = LockedContainer::open(path_str).unwrap();
        let c2 = locked.unlock("admin", "adminpassword").unwrap();
        assert_eq!(
            c2.read_at(file_id, 0, content.len() as u32).unwrap(),
            content
        );
        c2.close().unwrap();

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&src);
    }

    /// Сценарий, о котором сообщил пользователь: Desktop и Web открывают
    /// один контейнер одновременно; импорт в одной сессии должен стать
    /// виден другой сразу после `commit()`, не дожидаясь, пока первая
    /// сессия закроется. До введения `commit()` (было только `close(self)`,
    /// потребляющий Container) промежуточные изменения были видны только
    /// в памяти открывшей их сессии до её полного закрытия.
    #[test]
    fn commit_without_close_is_visible_to_a_second_reader() {
        let path = temp_container_path("commit_mid_session");
        let path_str = path.to_str().unwrap();
        let (mut c, _r) = Container::create(path_str, "admin", "adminpassword").unwrap();

        // До commit() — второй читатель не должен видеть файл. Намеренно
        // НЕ вызываем close() на чисто читающей сессии — иначе её
        // безобидный commit() продвинул бы version_counter и создал ложный
        // конфликт для параллельной сессии `c`, которая как раз собирается
        // писать (см. CoveError::Conflict и dirty-флаг в commit()) — сама
        // эта ситуация (незакрытая read-only сессия) тоже часть того, что
        // здесь проверяется.
        let locked_before = LockedContainer::open(path_str).unwrap();
        let c_before = locked_before.unlock("admin", "adminpassword").unwrap();
        assert!(c_before.list_dir(ROOT_FOLDER_ID).unwrap().is_empty());
        drop(c_before);

        let content = b"visible without full close".to_vec();
        let src = write_temp_source_file("commit_mid_session", &content);
        let file_id = c.import_file(src.to_str().unwrap(), ROOT_FOLDER_ID).unwrap();
        c.commit().unwrap();

        // Контейнер остаётся рабочим после commit() — не потреблён, можно
        // продолжать читать/писать в этой же сессии.
        assert_eq!(
            c.read_at(file_id, 0, content.len() as u32).unwrap(),
            content
        );

        let locked_after = LockedContainer::open(path_str).unwrap();
        let c_after = locked_after.unlock("admin", "adminpassword").unwrap();
        assert_eq!(
            c_after.read_at(file_id, 0, content.len() as u32).unwrap(),
            content
        );
        drop(c_after); // не close() — та же причина, что и у c_before выше

        // Второй commit() в этой же сессии (например, второе действие
        // пользователя) не должен ломать формат — file_table_backup_offset
        // должен указывать на только что записанную версию, не на устаревшую.
        let folder_id = c.create_folder("Ещё", ROOT_FOLDER_ID, None).unwrap();
        c.commit().unwrap();
        c.close().unwrap();

        let locked_final = LockedContainer::open(path_str).unwrap();
        let c_final = locked_final.unlock("admin", "adminpassword").unwrap();
        let entries = c_final.list_dir(ROOT_FOLDER_ID).unwrap();
        assert!(entries.iter().any(|e| e.file_id == file_id));
        assert!(entries.iter().any(|e| e.file_id == folder_id && e.flags.is_folder));
        c_final.close().unwrap();

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&src);
    }

    /// Точное воспроизведение реального репорта пользователя: сессия A
    /// (Desktop) создаёт папку и коммитит; сессия B (Web) была открыта
    /// раньше, ничего не меняла, но потом закрывается — раньше это молча
    /// стирало папку сессии A, восстановив старый (пустой) File Table.
    /// С dirty-флагом сессия B, не имея своих правок, должна тихо
    /// НИЧЕГО не писать при закрытии, а не затирать чужой commit.
    #[test]
    fn stale_read_only_session_does_not_erase_concurrent_commit() {
        let path = temp_container_path("stale_reader_no_erase");
        let path_str = path.to_str().unwrap();
        let (c_a, _r) = Container::create(path_str, "admin", "adminpassword").unwrap();

        // Сессия B открывается ДО того, как A что-то создаёт — как
        // залипшая веб-вкладка, открытая заранее.
        let locked_b = LockedContainer::open(path_str).unwrap();
        let session_b = locked_b.unlock("admin", "adminpassword").unwrap();

        let mut session_a = c_a;
        let folder_id = session_a.create_folder("Видео", ROOT_FOLDER_ID, Some("video")).unwrap();
        session_a.commit().unwrap();
        session_a.close().unwrap();

        // Сессия B ничего не меняла — её close() не должен стереть папку,
        // которую только что закоммитила A.
        session_b.close().unwrap();

        let locked_check = LockedContainer::open(path_str).unwrap();
        let check = locked_check.unlock("admin", "adminpassword").unwrap();
        let entries = check.list_dir(ROOT_FOLDER_ID).unwrap();
        assert!(
            entries.iter().any(|e| e.file_id == folder_id && e.flags.is_folder && e.folder_category.as_deref() == Some("video")),
            "папка сессии A должна пережить close() ничего не менявшей сессии B, но её нет: {entries:?}"
        );
        check.close().unwrap();

        let _ = std::fs::remove_file(&path);
    }

    /// Симметричный случай: если у устаревшей сессии ЕСТЬ собственные
    /// несохранённые правки, commit() должен явно отказать (Conflict), а
    /// не тихо потерять либо чужие, либо свои изменения.
    #[test]
    fn stale_session_with_pending_edit_gets_loud_conflict_not_silent_loss() {
        let path = temp_container_path("stale_reader_conflict");
        let path_str = path.to_str().unwrap();
        let (c_a, _r) = Container::create(path_str, "admin", "adminpassword").unwrap();

        let locked_b = LockedContainer::open(path_str).unwrap();
        let mut session_b = locked_b.unlock("admin", "adminpassword").unwrap();

        let mut session_a = c_a;
        session_a.create_folder("Видео", ROOT_FOLDER_ID, Some("video")).unwrap();
        session_a.commit().unwrap();
        session_a.close().unwrap();

        // У сессии B тоже есть своя (более старая, ещё не увидевшая папку A)
        // правка — её нельзя молча ни принять (потеряет папку A), ни
        // отбросить без предупреждения (пользователь решит, что его правка
        // сохранилась). Явная ошибка — единственный честный вариант.
        session_b.create_folder("Другое", ROOT_FOLDER_ID, None).unwrap();
        let result = session_b.commit();
        assert!(
            matches!(result, Err(CoveError::Conflict)),
            "ожидался Conflict, получено: {result:?}"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// Точный сценарий, который попросил пользователь: загрузил файл через
    /// Web — хочет увидеть его в уже открытой Desktop-сессии "сразу", без
    /// повторного логина. `reload()` не требует пароля (DEK уже в памяти) и
    /// подхватывает изменения именно так.
    #[test]
    fn reload_picks_up_changes_from_another_session_without_password() {
        let path = temp_container_path("reload_cross_session");
        let path_str = path.to_str().unwrap();
        let (c_a, _r) = Container::create(path_str, "admin", "adminpassword").unwrap();

        // "Desktop" — открыт заранее, ничего пока не знает о будущей папке.
        let mut desktop = c_a;
        assert!(desktop.list_dir(ROOT_FOLDER_ID).unwrap().is_empty());

        // "Web" — отдельная сессия, создаёт папку и коммитит.
        let locked_web = LockedContainer::open(path_str).unwrap();
        let mut web = locked_web.unlock("admin", "adminpassword").unwrap();
        let folder_id = web.create_folder("ИзВеба", ROOT_FOLDER_ID, Some("video")).unwrap();
        web.commit().unwrap();

        // До reload() десктоп ещё не видит папку — это не автоматическая
        // магия, а явный (пусть и дешёвый) шаг.
        assert!(desktop.list_dir(ROOT_FOLDER_ID).unwrap().is_empty());

        let changed = desktop.reload().unwrap();
        assert!(changed, "reload() должен был обнаружить новую версию на диске");
        let entries = desktop.list_dir(ROOT_FOLDER_ID).unwrap();
        assert!(entries.iter().any(|e| e.file_id == folder_id && e.flags.is_folder));

        // Повторный reload() без новых изменений — дешёвый no-op, не ошибка.
        assert!(!desktop.reload().unwrap());

        desktop.close().unwrap();
        web.close().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn multi_block_read_matches_content() {
        let path = temp_container_path("multiblock");
        let path_str = path.to_str().unwrap();
        let (mut c, _r) = Container::create(path_str, "admin", "adminpassword").unwrap();
        // Тестовое переопределение размера блока — живёт только в этой сессии
        // (Header на диске не переписывается после create()), но именно
        // поэтому годится: import+read_at ниже не переоткрывают контейнер.
        c.header.block_size = 64;

        let content: Vec<u8> = (0..500u32).map(|i| (i % 251) as u8).collect();
        let src = write_temp_source_file("multiblock", &content);
        let file_id = c.import_file(src.to_str().unwrap(), ROOT_FOLDER_ID).unwrap();

        let entry = c
            .list_dir(ROOT_FOLDER_ID)
            .unwrap()
            .into_iter()
            .find(|e| e.file_id == file_id)
            .unwrap();
        assert!(
            entry.block_list.len() > 1,
            "500 байт при block_size=64 должны дать несколько блоков"
        );

        assert_eq!(
            c.read_at(file_id, 0, content.len() as u32).unwrap(),
            content
        );
        // Чтение через границу блока (блоки по 64 байта, offset 60 → блок 0 и блок 1).
        assert_eq!(c.read_at(file_id, 60, 20).unwrap(), &content[60..80]);

        c.close().unwrap();
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&src);
    }

    #[test]
    fn folders_and_move() {
        let path = temp_container_path("folders");
        let path_str = path.to_str().unwrap();
        let (mut c, _r) = Container::create(path_str, "admin", "adminpassword").unwrap();

        let folder_id = c.create_folder("Фото", ROOT_FOLDER_ID, None).unwrap();
        let content = b"a photo, sort of".to_vec();
        let src = write_temp_source_file("folder_file", &content);
        let file_id = c.import_file(src.to_str().unwrap(), ROOT_FOLDER_ID).unwrap();

        assert_eq!(c.list_dir(ROOT_FOLDER_ID).unwrap().len(), 2); // папка + файл
        assert!(c.list_dir(folder_id).unwrap().is_empty());

        c.move_file(file_id, folder_id).unwrap();
        assert_eq!(c.list_dir(ROOT_FOLDER_ID).unwrap().len(), 1); // осталась только папка
        assert_eq!(c.list_dir(folder_id).unwrap().len(), 1);

        assert!(matches!(
            c.move_file(file_id, 999_999),
            Err(CoveError::NotFound)
        ));

        c.close().unwrap();
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&src);
    }

    /// По прямому запросу пользователя: папка "привязывается" к категории
    /// вкладки, в которой создана, а не пересчитывается по содержимому —
    /// см. `FileEntry::folder_category`. Проверяет и сохранение значения
    /// через close/reopen (не только в памяти).
    #[test]
    fn folder_category_persists_and_is_independent_per_folder() {
        let path = temp_container_path("folder_category");
        let path_str = path.to_str().unwrap();
        let (mut c, _r) = Container::create(path_str, "admin", "adminpassword").unwrap();

        let photo_folder = c.create_folder("Отпуск", ROOT_FOLDER_ID, Some("image")).unwrap();
        let doc_folder = c.create_folder("Договоры", ROOT_FOLDER_ID, Some("document")).unwrap();
        let plain_folder = c.create_folder("Разное", ROOT_FOLDER_ID, None).unwrap();

        let get = |c: &Container, id: FileId| -> Option<String> {
            c.list_dir(ROOT_FOLDER_ID)
                .unwrap()
                .into_iter()
                .find(|e| e.file_id == id)
                .unwrap()
                .folder_category
        };
        assert_eq!(get(&c, photo_folder), Some("image".to_string()));
        assert_eq!(get(&c, doc_folder), Some("document".to_string()));
        assert_eq!(get(&c, plain_folder), None);

        c.close().unwrap();
        let locked = LockedContainer::open(path_str).unwrap();
        let reopened = locked.unlock("admin", "adminpassword").unwrap();
        assert_eq!(get(&reopened, photo_folder), Some("image".to_string()));
        assert_eq!(get(&reopened, doc_folder), Some("document".to_string()));
        assert_eq!(get(&reopened, plain_folder), None);

        reopened.close().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn trash_restore_and_permanent_delete() {
        let path = temp_container_path("trash");
        let path_str = path.to_str().unwrap();
        let (mut c, _r) = Container::create(path_str, "admin", "adminpassword").unwrap();
        let content = b"disposable".to_vec();
        let src = write_temp_source_file("trash", &content);
        let file_id = c.import_file(src.to_str().unwrap(), ROOT_FOLDER_ID).unwrap();

        c.delete_file(file_id).unwrap();
        assert!(c.list_dir(ROOT_FOLDER_ID).unwrap().is_empty());
        assert_eq!(c.list_trash().len(), 1);

        c.restore_file(file_id).unwrap();
        assert_eq!(c.list_dir(ROOT_FOLDER_ID).unwrap().len(), 1);
        assert!(c.list_trash().is_empty());

        c.delete_file(file_id).unwrap(); // -> в корзину
        c.delete_file(file_id).unwrap(); // -> окончательно
        assert!(c.list_trash().is_empty());
        assert!(matches!(
            c.restore_file(file_id),
            Err(CoveError::NotFound)
        ));

        c.close().unwrap();
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&src);
    }

    #[test]
    fn rename_and_replace_content() {
        let path = temp_container_path("rename_replace");
        let path_str = path.to_str().unwrap();
        let (mut c, _r) = Container::create(path_str, "admin", "adminpassword").unwrap();
        let content = b"version one".to_vec();
        let src = write_temp_source_file("v1", &content);
        let file_id = c.import_file(src.to_str().unwrap(), ROOT_FOLDER_ID).unwrap();

        c.rename_file(file_id, "renamed.txt").unwrap();
        assert_eq!(c.list_dir(ROOT_FOLDER_ID).unwrap()[0].name, "renamed.txt");

        let content2 = b"version two, longer than before".to_vec();
        let src2 = write_temp_source_file("v2", &content2);
        c.replace_file_content(file_id, src2.to_str().unwrap())
            .unwrap();
        assert_eq!(
            c.read_at(file_id, 0, content2.len() as u32).unwrap(),
            content2
        );
        assert_eq!(c.file_size(file_id).unwrap(), content2.len() as u64);

        c.close().unwrap();
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_file(&src2);
    }

    #[test]
    fn read_only_cannot_write() {
        let path = temp_container_path("readonly");
        let path_str = path.to_str().unwrap();
        let (mut c, _r) = Container::create(path_str, "admin", "adminpassword").unwrap();
        c.add_user("viewer", "viewerpassword", Role::ReadOnly)
            .unwrap();
        c.close().unwrap();

        let locked = LockedContainer::open(path_str).unwrap();
        let mut viewer = locked.unlock("viewer", "viewerpassword").unwrap();

        let src = write_temp_source_file("readonly", b"nope");
        assert!(matches!(
            viewer.import_file(src.to_str().unwrap(), ROOT_FOLDER_ID),
            Err(CoveError::PermissionDenied)
        ));
        assert!(matches!(
            viewer.create_folder("x", ROOT_FOLDER_ID, None),
            Err(CoveError::PermissionDenied)
        ));

        viewer.close().unwrap();
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&src);
    }

    #[test]
    fn thumbnail_lifecycle() {
        let path = temp_container_path("thumbnail");
        let path_str = path.to_str().unwrap();
        let (mut c, _r) = Container::create(path_str, "admin", "adminpassword").unwrap();

        let content = b"pretend this is a photo".to_vec();
        let src = write_temp_source_file("photo", &content);
        let file_id = c.import_file(src.to_str().unwrap(), ROOT_FOLDER_ID).unwrap();

        assert!(c.find_thumbnail(file_id).is_none());

        let thumb_bytes = b"pretend this is a small png".to_vec();
        let thumb_id = c.thumbnail(file_id, &thumb_bytes).unwrap();
        assert_eq!(c.find_thumbnail(file_id), Some(thumb_id));
        assert_eq!(c.read_at(thumb_id, 0, thumb_bytes.len() as u32).unwrap(), thumb_bytes);

        // Миниатюры — internal, в обычном листинге их быть не должно.
        let listed = c.list_dir(ROOT_FOLDER_ID).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].file_id, file_id);

        // Повторная генерация обновляет ту же запись, а не плодит дубликаты.
        let thumb_bytes_v2 = b"pretend this is an updated png, longer".to_vec();
        let thumb_id_v2 = c.thumbnail(file_id, &thumb_bytes_v2).unwrap();
        assert_eq!(thumb_id_v2, thumb_id);
        assert_eq!(
            c.read_at(thumb_id, 0, thumb_bytes_v2.len() as u32).unwrap(),
            thumb_bytes_v2
        );

        // Замена содержимого файла инвалидирует миниатюру.
        let content2 = write_temp_source_file("photo_v2", b"new content entirely");
        c.replace_file_content(file_id, content2.to_str().unwrap())
            .unwrap();
        assert!(c.find_thumbnail(file_id).is_none());

        // Регенерируем и проверяем, что окончательное удаление файла тянет
        // за собой и миниатюру.
        let thumb_id_v3 = c.thumbnail(file_id, &thumb_bytes).unwrap();
        c.delete_file(file_id).unwrap(); // -> корзина
        c.delete_file(file_id).unwrap(); // -> окончательно
        assert!(c.find_thumbnail(file_id).is_none());
        assert!(matches!(
            c.read_at(thumb_id_v3, 0, 1),
            Err(CoveError::NotFound)
        ));

        c.close().unwrap();
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_file(&content2);
    }

    #[test]
    fn thumbnail_for_missing_file_fails() {
        let path = temp_container_path("thumbnail_missing");
        let path_str = path.to_str().unwrap();
        let (mut c, _r) = Container::create(path_str, "admin", "adminpassword").unwrap();
        assert!(matches!(
            c.thumbnail(999_999, b"data"),
            Err(CoveError::NotFound)
        ));
        c.close().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn search_by_name_extension_category_and_size() {
        let path = temp_container_path("search_basic");
        let path_str = path.to_str().unwrap();
        let (mut c, _r) = Container::create(path_str, "admin", "adminpassword").unwrap();

        let photo = write_temp_source_file("отпуск", &[0u8; 100]);
        let photo_renamed = photo.with_file_name("отпуск.jpg");
        std::fs::rename(&photo, &photo_renamed).unwrap();
        let photo_id = c.import_file(photo_renamed.to_str().unwrap(), ROOT_FOLDER_ID).unwrap();

        let doc = write_temp_source_file("отчёт", &[0u8; 5000]);
        let doc_renamed = doc.with_file_name("отчёт.pdf");
        std::fs::rename(&doc, &doc_renamed).unwrap();
        c.import_file(doc_renamed.to_str().unwrap(), ROOT_FOLDER_ID).unwrap();

        let by_name = c
            .search(SearchQuery {
                name_contains: Some("отпуск".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(by_name.len(), 1);
        assert_eq!(by_name[0].file_id, photo_id);

        let by_ext = c
            .search(SearchQuery {
                extension: Some("PDF".to_string()), // регистр не важен
                ..Default::default()
            })
            .unwrap();
        assert_eq!(by_ext.len(), 1);
        assert_eq!(by_ext[0].name, "отчёт.pdf");

        let images = c
            .search(SearchQuery {
                category: Some("image".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].file_id, photo_id);

        let small_only = c
            .search(SearchQuery {
                max_size: Some(1000),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(small_only.len(), 1);
        assert_eq!(small_only[0].file_id, photo_id);

        c.close().unwrap();
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&photo_renamed);
        let _ = std::fs::remove_file(&doc_renamed);
    }

    #[test]
    fn search_by_folder_is_recursive() {
        let path = temp_container_path("search_folder");
        let path_str = path.to_str().unwrap();
        let (mut c, _r) = Container::create(path_str, "admin", "adminpassword").unwrap();

        let outer = c.create_folder("Снаружи", ROOT_FOLDER_ID, None).unwrap();
        let inner = c.create_folder("Внутри", outer, None).unwrap();
        let src = write_temp_source_file("deep", b"content");
        let deep_id = c.import_file(src.to_str().unwrap(), inner).unwrap();
        let root_src = write_temp_source_file("shallow", b"content");
        let shallow_id = c.import_file(root_src.to_str().unwrap(), ROOT_FOLDER_ID).unwrap();

        let within_outer = c
            .search(SearchQuery {
                folder_id: Some(outer),
                ..Default::default()
            })
            .unwrap();
        // Файл в inner (вложенной папке outer) находится, сама папка inner —
        // тоже (она законная часть поддерева outer), а файл в корне — нет.
        assert!(within_outer.iter().any(|e| e.file_id == deep_id));
        assert!(within_outer.iter().any(|e| e.file_id == inner));
        assert!(within_outer.iter().all(|e| e.file_id != shallow_id));

        c.close().unwrap();
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_file(&root_src);
    }

    #[test]
    fn move_folder_into_own_subfolder_rejected() {
        let path = temp_container_path("move_cycle");
        let path_str = path.to_str().unwrap();
        let (mut c, _r) = Container::create(path_str, "admin", "adminpassword").unwrap();

        let outer = c.create_folder("Outer", ROOT_FOLDER_ID, None).unwrap();
        let inner = c.create_folder("Inner", outer, None).unwrap();

        assert!(matches!(
            c.move_file(outer, inner),
            Err(CoveError::FormatError { .. })
        ));
        assert!(matches!(
            c.move_file(outer, outer),
            Err(CoveError::FormatError { .. })
        ));

        c.close().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn search_excludes_trash_and_internal() {
        let path = temp_container_path("search_excludes");
        let path_str = path.to_str().unwrap();
        let (mut c, _r) = Container::create(path_str, "admin", "adminpassword").unwrap();

        let src = write_temp_source_file("temp", b"content");
        let file_id = c.import_file(src.to_str().unwrap(), ROOT_FOLDER_ID).unwrap();
        c.thumbnail(file_id, b"fake png bytes").unwrap();
        c.delete_file(file_id).unwrap(); // -> корзина

        let results = c.search(SearchQuery::default()).unwrap();
        assert!(results.is_empty());

        c.close().unwrap();
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&src);
    }

    #[test]
    fn favorite_toggle_and_search() {
        let path = temp_container_path("favorite");
        let path_str = path.to_str().unwrap();
        let (mut c, _r) = Container::create(path_str, "admin", "adminpassword").unwrap();

        let src1 = write_temp_source_file("a", b"one");
        let id1 = c.import_file(src1.to_str().unwrap(), ROOT_FOLDER_ID).unwrap();
        let src2 = write_temp_source_file("b", b"two");
        let id2 = c.import_file(src2.to_str().unwrap(), ROOT_FOLDER_ID).unwrap();

        assert!(c
            .search(SearchQuery { favorite: Some(true), ..Default::default() })
            .unwrap()
            .is_empty());

        c.set_favorite(id1, true).unwrap();
        let favorites = c
            .search(SearchQuery { favorite: Some(true), ..Default::default() })
            .unwrap();
        assert_eq!(favorites.len(), 1);
        assert_eq!(favorites[0].file_id, id1);

        c.set_favorite(id1, false).unwrap();
        assert!(c
            .search(SearchQuery { favorite: Some(true), ..Default::default() })
            .unwrap()
            .is_empty());

        assert!(matches!(
            c.set_favorite(999_999, true),
            Err(CoveError::NotFound)
        ));

        let _ = id2;
        c.close().unwrap();
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&src1);
        let _ = std::fs::remove_file(&src2);
    }

    #[test]
    fn read_only_cannot_set_favorite() {
        let path = temp_container_path("favorite_readonly");
        let path_str = path.to_str().unwrap();
        let (mut c, _r) = Container::create(path_str, "admin", "adminpassword").unwrap();
        c.add_user("viewer", "viewerpassword", Role::ReadOnly).unwrap();
        let src = write_temp_source_file("f", b"content");
        let file_id = c.import_file(src.to_str().unwrap(), ROOT_FOLDER_ID).unwrap();
        c.close().unwrap();

        let locked = LockedContainer::open(path_str).unwrap();
        let mut viewer = locked.unlock("viewer", "viewerpassword").unwrap();
        assert!(matches!(
            viewer.set_favorite(file_id, true),
            Err(CoveError::PermissionDenied)
        ));
        viewer.close().unwrap();

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&src);
    }

    #[test]
    fn list_users_excludes_recovery_slot() {
        let path = temp_container_path("list_users");
        let path_str = path.to_str().unwrap();
        let (mut c, _r) = Container::create(path_str, "admin", "adminpassword").unwrap();
        c.add_user("viewer", "viewerpassword", Role::ReadOnly).unwrap();

        let mut users = c.list_users();
        users.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            users,
            vec![
                ("admin".to_string(), Role::Admin),
                ("viewer".to_string(), Role::ReadOnly),
            ]
        );

        c.close().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn set_user_role_changes_permissions() {
        let path = temp_container_path("set_role");
        let path_str = path.to_str().unwrap();
        let (mut c, _r) = Container::create(path_str, "admin", "adminpassword").unwrap();
        c.add_user("viewer", "viewerpassword", Role::ReadOnly).unwrap();
        c.set_user_role("viewer", Role::Admin).unwrap();
        c.close().unwrap();

        let locked = LockedContainer::open(path_str).unwrap();
        let mut viewer = locked.unlock("viewer", "viewerpassword").unwrap();
        assert_eq!(viewer.current_role(), Role::Admin);
        // Раньше read-only, теперь admin — должен смочь то, что не мог.
        viewer.add_user("third", "thirdpassword123", Role::ReadOnly).unwrap();
        viewer.close().unwrap();

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn cannot_demote_last_admin() {
        let path = temp_container_path("demote_last_admin");
        let path_str = path.to_str().unwrap();
        let (mut c, _r) = Container::create(path_str, "admin", "adminpassword").unwrap();
        assert!(matches!(
            c.set_user_role("admin", Role::ReadOnly),
            Err(CoveError::PermissionDenied)
        ));
        c.close().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn set_user_role_for_missing_user_fails() {
        let path = temp_container_path("set_role_missing");
        let path_str = path.to_str().unwrap();
        let (mut c, _r) = Container::create(path_str, "admin", "adminpassword").unwrap();
        assert!(matches!(
            c.set_user_role("nobody", Role::Admin),
            Err(CoveError::NotFound)
        ));
        c.close().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn import_file_from_bytes_roundtrip() {
        let path = temp_container_path("import_bytes");
        let path_str = path.to_str().unwrap();
        let (mut c, _r) = Container::create(path_str, "admin", "adminpassword").unwrap();

        let content = b"uploaded straight from an HTTP request body".to_vec();
        let file_id = c
            .import_file_from_bytes("upload.txt", ROOT_FOLDER_ID, &content)
            .unwrap();

        let entry = c
            .list_dir(ROOT_FOLDER_ID)
            .unwrap()
            .into_iter()
            .find(|e| e.file_id == file_id)
            .unwrap();
        assert_eq!(entry.name, "upload.txt");
        assert_eq!(entry.size, content.len() as u64);
        assert_eq!(entry.mime_hint.as_deref(), Some("text/plain"));
        assert_eq!(c.read_at(file_id, 0, content.len() as u32).unwrap(), content);

        c.close().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_only_cannot_import_from_bytes() {
        let path = temp_container_path("import_bytes_readonly");
        let path_str = path.to_str().unwrap();
        let (mut c, _r) = Container::create(path_str, "admin", "adminpassword").unwrap();
        c.add_user("viewer", "viewerpassword", Role::ReadOnly).unwrap();
        c.close().unwrap();

        let locked = LockedContainer::open(path_str).unwrap();
        let mut viewer = locked.unlock("viewer", "viewerpassword").unwrap();
        assert!(matches!(
            viewer.import_file_from_bytes("x.txt", ROOT_FOLDER_ID, b"data"),
            Err(CoveError::PermissionDenied)
        ));
        viewer.close().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// Точечная запись File Table (ROADMAP.md, Фаза 2/6) на уровне
    /// `Container`, а не только `file_table::encode_file_table_incremental`
    /// напрямую: заполняем таблицу так, чтобы она заняла ДВЕ страницы,
    /// коммитим, правим одну запись (переносим её в первую страницу),
    /// коммитим снова, закрываем и переоткрываем — все записи должны
    /// остаться на месте вне зависимости от того, какая страница
    /// переиспользовалась из кэша, а какая перешифровывалась заново.
    #[test]
    fn commit_after_partial_edit_survives_close_reopen_across_pages() {
        let path = temp_container_path("incremental_pages");
        let path_str = path.to_str().unwrap();
        let (mut c, _r) = Container::create(path_str, "admin", "adminpassword").unwrap();

        let total = file_table::MAX_ENTRIES_PER_PAGE + 5; // гарантированно 2 страницы
        let mut ids = Vec::with_capacity(total);
        for i in 0..total {
            let id = c
                .import_file_from_bytes(&format!("file_{i}.txt"), ROOT_FOLDER_ID, b"x")
                .unwrap();
            ids.push(id);
        }
        c.commit().unwrap();

        // Правим ровно одну запись во ВТОРОЙ странице (индекс >=
        // MAX_ENTRIES_PER_PAGE по порядку добавления) — первая страница
        // должна остаться нетронутой и переиспользоваться из кэша.
        let target = ids[file_table::MAX_ENTRIES_PER_PAGE + 2];
        c.rename_file(target, "переименован.txt").unwrap();
        c.commit().unwrap();
        c.close().unwrap();

        let locked = LockedContainer::open(path_str).unwrap();
        let reopened = locked.unlock("admin", "adminpassword").unwrap();
        let entries = reopened.list_dir(ROOT_FOLDER_ID).unwrap();
        assert_eq!(entries.len(), total);
        let renamed = entries.iter().find(|e| e.file_id == target).unwrap();
        assert_eq!(renamed.name, "переименован.txt");
        // Все остальные файлы (в т.ч. вся первая, нетронутая, страница) —
        // тоже на месте с исходными именами.
        for (i, &id) in ids.iter().enumerate() {
            if id == target {
                continue;
            }
            let e = entries.iter().find(|e| e.file_id == id).unwrap();
            assert_eq!(e.name, format!("file_{i}.txt"));
        }
        reopened.close().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// Ядро "восстановления при частичном повреждении File Table" на
    /// уровне полного `Container`, а не только `file_table`-модуля:
    /// специально портим шифртекст одной страницы прямо на диске
    /// (имитация повреждённого/битого сектора), затем открываем контейнер
    /// заново — он обязан открыться (не отказать целиком) и честно
    /// сообщить, какая страница потеряна, при этом дав доступ ко всем
    /// остальным записям.
    #[test]
    fn reopen_with_one_corrupted_page_recovers_the_rest() {
        let path = temp_container_path("partial_corruption");
        let path_str = path.to_str().unwrap();
        let (mut c, _r) = Container::create(path_str, "admin", "adminpassword").unwrap();

        let total = file_table::MAX_ENTRIES_PER_PAGE * 2 + 3; // 3 страницы
        let mut ids = Vec::with_capacity(total);
        for i in 0..total {
            let id = c
                .import_file_from_bytes(&format!("file_{i}.txt"), ROOT_FOLDER_ID, b"x")
                .unwrap();
            ids.push(id);
        }
        c.close().unwrap();

        // Находим и портим шифртекст страницы 1 (средней) прямо в файле на
        // диске — та же структура блоба, что использует container::commit()
        // (superblock -> file_table_offset/len -> [page_count][len][bytes]...).
        {
            let mut file = OpenOptions::new().read(true).write(true).open(path_str).unwrap();
            let locked = LockedContainer::open(path_str).unwrap();
            let (pointer, _) = read_valid_commit_pointer(&mut file, &locked.header).unwrap();
            let mut sb_blob = [0u8; superblock::BLOB_LEN];
            file.seek(SeekFrom::Start(pointer.superblock_offset)).unwrap();
            file.read_exact(&mut sb_blob).unwrap();
            // Расшифровать superblock тут нечем без DEK — вместо этого
            // читаем офсеты через саму Container-сессию перед close() было
            // бы сложнее; проще: найдём таблицу перебором известной
            // структуры через уже открытую (но ещё не закрытую) copy. Для
            // простоты теста откроем заново с паролем, чтобы получить
            // актуальный Superblock напрямую.
            drop(locked);
            let locked2 = LockedContainer::open(path_str).unwrap();
            let reopened = locked2.unlock("admin", "adminpassword").unwrap();
            let sb_offset = reopened.superblock.file_table_offset;
            let sb_len = reopened.superblock.file_table_len;
            // НЕ close()! commit() (который вызывает close()) всегда пишет
            // новую версию на новый offset, даже если ничего не менялось
            // (см. doc-комментарий у commit() — версию продвигает сам факт
            // совпадения version_counter, а не значение dirty) — тогда
            // sb_offset/sb_len выше указывали бы уже на СТАРУЮ, неактивную
            // копию, и порча байт по этому адресу ничего бы не задела.
            drop(reopened);

            // Портим байт в середине региона File Table — почти наверняка
            // попадёт в шифртекст одной из трёх страниц, а не точно в
            // page_count/page_len framing (которое всего 4+4+4 = 12 байт из
            // региона, занимающего десятки КБ на 3 страницы).
            let flip_at = sb_offset + sb_len / 2;
            file.seek(SeekFrom::Start(flip_at)).unwrap();
            let mut byte = [0u8; 1];
            file.read_exact(&mut byte).unwrap();
            byte[0] ^= 0xFF;
            file.seek(SeekFrom::Start(flip_at)).unwrap();
            file.write_all(&byte).unwrap();
        }

        let locked = LockedContainer::open(path_str).unwrap();
        let recovered = locked
            .unlock("admin", "adminpassword")
            .expect("контейнер должен открыться несмотря на повреждённую страницу");

        assert!(
            !recovered.lost_file_table_pages().is_empty(),
            "должна быть зафиксирована хотя бы одна потерянная страница"
        );
        let entries = recovered.list_dir(ROOT_FOLDER_ID).unwrap();
        // Часть записей потеряна (та самая испорченная страница), но НЕ все.
        assert!(!entries.is_empty(), "остальные страницы должны были уцелеть");
        assert!(
            entries.len() < total,
            "повреждённая страница должна была унести часть записей, иначе тест ничего не проверяет"
        );
        recovered.close().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// Компактификация (ROADMAP.md, "Компактификация свободных блоков
    /// данных") — основной сценарий: импортируем крупный файл, окончательно
    /// удаляем его (первый delete_file — в корзину, второй — насовсем, тем
    /// самым его блоки становятся орфанами), commit — файл на диске заметно
    /// вырос за счёт содержимого, которое больше ни на что не ссылается.
    /// compact() обязан вернуть контейнер к размеру, близкому к тому, что
    /// нужен только оставшимся живым данным, и вернуть положительное число
    /// освобождённых байт.
    #[test]
    fn compact_reclaims_space_from_orphaned_blocks() {
        let path = temp_container_path("compact_basic");
        let path_str = path.to_str().unwrap();
        let (mut c, _r) = Container::create(path_str, "admin", "adminpassword").unwrap();

        let keep_content = b"this file must survive compaction".to_vec();
        let keep_id = c.import_file_from_bytes("keep.bin", ROOT_FOLDER_ID, &keep_content).unwrap();

        // ~2МиБ орфанного содержимого — достаточно крупно, чтобы разница в
        // размере файла до/после была однозначной, а не шумом от метаданных.
        let big_content = vec![0x5Au8; 2 * 1024 * 1024];
        let doomed_id = c.import_file_from_bytes("doomed.bin", ROOT_FOLDER_ID, &big_content).unwrap();
        c.delete_file(doomed_id).unwrap(); // в корзину
        c.delete_file(doomed_id).unwrap(); // окончательно — блоки осиротели
        c.commit().unwrap();

        let size_before = std::fs::metadata(path_str).unwrap().len();
        let freed = c.compact().unwrap();
        let size_after = std::fs::metadata(path_str).unwrap().len();

        assert_eq!(size_before - size_after, freed);
        assert!(
            freed > 1024 * 1024,
            "ожидали освободить хотя бы ~1МиБ орфанного содержимого, освободили {freed}"
        );

        // Оставшийся файл по-прежнему на месте и читается корректно — а не
        // просто "запись в File Table цела", а именно байты содержимого.
        assert_eq!(
            c.read_at(keep_id, 0, keep_content.len() as u32).unwrap(),
            keep_content
        );

        // Переживает закрытие/переоткрытие после компактификации — новые
        // offset'ы блоков честно попали в File Table, а не потерялись.
        c.close().unwrap();
        let locked = LockedContainer::open(path_str).unwrap();
        let reopened = locked.unlock("admin", "adminpassword").unwrap();
        assert_eq!(
            reopened.read_at(keep_id, 0, keep_content.len() as u32).unwrap(),
            keep_content
        );
        assert!(reopened.list_dir(ROOT_FOLDER_ID).unwrap().iter().all(|e| e.file_id != doomed_id));
        reopened.close().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// Второй пользователь (не админ) должен по-прежнему логиниться после
    /// compact() — keyslots копируются байт-в-байт, но стоит явно
    /// проверить, что реальный вход всё ещё работает, а не просто "байты
    /// совпадают".
    #[test]
    fn compact_preserves_other_users_login() {
        let path = temp_container_path("compact_users");
        let path_str = path.to_str().unwrap();
        let (mut c, _r) = Container::create(path_str, "admin", "adminpassword").unwrap();
        c.add_user("viewer", "viewerpassword", Role::ReadOnly).unwrap();
        c.commit().unwrap();

        c.compact().unwrap();
        c.close().unwrap();

        let locked = LockedContainer::open(path_str).unwrap();
        let viewer = locked.unlock("viewer", "viewerpassword").unwrap();
        assert_eq!(viewer.current_role(), Role::ReadOnly);
        viewer.close().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// `compact()` требует прав на запись (как `delete_file`/
    /// `replace_file_content`, которые и создают орфанов), а не прав
    /// администратора — это уборка за собственными действиями пользователя,
    /// а не смена структуры пользователей/ролей контейнера. ReadOnly не
    /// может ни удалить файл, ни компактифицировать за собой.
    #[test]
    fn compact_requires_write_permission() {
        let path = temp_container_path("compact_permission");
        let path_str = path.to_str().unwrap();
        let (mut c, _r) = Container::create(path_str, "admin", "adminpassword").unwrap();
        c.add_user("viewer", "viewerpassword", Role::ReadOnly).unwrap();
        c.close().unwrap();

        let locked = LockedContainer::open(path_str).unwrap();
        let mut viewer = locked.unlock("viewer", "viewerpassword").unwrap();
        assert!(matches!(viewer.compact(), Err(CoveError::PermissionDenied)));
        viewer.close().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// Обычный пользователь с правом записи (не администратор) должен
    /// иметь возможность освободить место, которое сам же и осиротил
    /// удалением своего файла — раньше это требовало прав администратора,
    /// что не соответствовало тому, кто реально мог создать орфанов.
    #[test]
    fn compact_allowed_for_non_admin_writer() {
        let path = temp_container_path("compact_readwrite");
        let path_str = path.to_str().unwrap();
        let (mut c, _r) = Container::create(path_str, "admin", "adminpassword").unwrap();
        c.add_user("editor", "editorpassword", Role::ReadWrite).unwrap();
        c.close().unwrap();

        let locked = LockedContainer::open(path_str).unwrap();
        let mut editor = locked.unlock("editor", "editorpassword").unwrap();
        let big_content = vec![0x7Bu8; 2 * 1024 * 1024];
        let id = editor.import_file_from_bytes("doomed.bin", ROOT_FOLDER_ID, &big_content).unwrap();
        editor.delete_file(id).unwrap();
        editor.delete_file(id).unwrap();
        editor.commit().unwrap();

        let freed = editor.compact().unwrap();
        assert!(freed > 1024 * 1024, "не-админ должен был реально освободить место");
        editor.close().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// Компактификация без единого орфана не должна ничего портить — нулевая
    /// экономия честно возвращается как 0, а не ошибка, и все файлы целы.
    #[test]
    fn compact_with_nothing_to_reclaim_is_a_safe_noop() {
        let path = temp_container_path("compact_noop");
        let path_str = path.to_str().unwrap();
        let (mut c, _r) = Container::create(path_str, "admin", "adminpassword").unwrap();
        let content = b"nothing to reclaim here".to_vec();
        let id = c.import_file_from_bytes("a.bin", ROOT_FOLDER_ID, &content).unwrap();
        c.commit().unwrap();

        c.compact().unwrap();
        assert_eq!(c.read_at(id, 0, content.len() as u32).unwrap(), content);
        c.close().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// Именно сценарий, который попросил пользователь: удалил файл, вышел
    /// (`close()`, тот же путь, что зовёт GUI при логауте на всех трёх
    /// платформах) — и БЕЗ единого явного вызова `compact()` файл базы
    /// реально стал меньше. Отдельно проверяем, что данные, которые не
    /// удалялись, при этом не пострадали.
    #[test]
    fn close_after_permanent_delete_shrinks_file_automatically() {
        let path = temp_container_path("auto_compact_on_close");
        let path_str = path.to_str().unwrap();
        let (mut c, _r) = Container::create(path_str, "admin", "adminpassword").unwrap();

        let keep_content = b"survives the automatic cleanup".to_vec();
        let keep_id = c.import_file_from_bytes("keep.bin", ROOT_FOLDER_ID, &keep_content).unwrap();

        let big_content = vec![0x99u8; 2 * 1024 * 1024];
        let doomed_id = c.import_file_from_bytes("doomed.bin", ROOT_FOLDER_ID, &big_content).unwrap();
        c.commit().unwrap();
        let size_before_delete = std::fs::metadata(path_str).unwrap().len();

        c.delete_file(doomed_id).unwrap(); // в корзину
        c.delete_file(doomed_id).unwrap(); // окончательно — блоки осиротели
        // Пользователь просто выходит — НЕ зовёт compact() сам.
        c.close().unwrap();

        let size_after_logout = std::fs::metadata(path_str).unwrap().len();
        assert!(
            size_after_logout < size_before_delete,
            "после выхода файл базы должен был стать меньше: было {size_before_delete}, стало {size_after_logout}"
        );

        let locked = LockedContainer::open(path_str).unwrap();
        let reopened = locked.unlock("admin", "adminpassword").unwrap();
        assert_eq!(
            reopened.read_at(keep_id, 0, keep_content.len() as u32).unwrap(),
            keep_content
        );
        assert!(reopened.list_dir(ROOT_FOLDER_ID).unwrap().iter().all(|e| e.file_id != doomed_id));
        reopened.close().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// Обратная сторона той же оптимизации: сессия, которая ничего не
    /// удаляла, при выходе не должна платить цену полной компактификации —
    /// `close()` в этом случае обязан остаться дешёвым `commit()`. Прямо
    /// замерить "не было полного перечитывания/переписывания блоков"
    /// сложно, но можно проверить наблюдаемое следствие: обычный commit
    /// СОХРАНЯЕТ `file_table_backup_offset` как отдельную ссылку на
    /// предыдущее поколение (Фаза 2/17), а `compact()` всегда схлопывает
    /// её в текущий offset (см. код `compact()` — "новая база, прежней
    /// истории для отката больше не существует"). Если после чистого
    /// close() без единого удаления backup-offset всё ещё отличается от
    /// текущего — это и есть доказательство, что сработал обычный commit,
    /// а не незаметный лишний compact().
    #[test]
    fn close_without_deletions_does_not_auto_compact() {
        let path = temp_container_path("no_auto_compact");
        let path_str = path.to_str().unwrap();
        let (mut c, _r) = Container::create(path_str, "admin", "adminpassword").unwrap();
        let content = b"just importing, never deleting".to_vec();
        c.import_file_from_bytes("a.bin", ROOT_FOLDER_ID, &content).unwrap();
        c.close().unwrap();

        let locked = LockedContainer::open(path_str).unwrap();
        let reopened = locked.unlock("admin", "adminpassword").unwrap();
        assert_ne!(
            reopened.superblock.file_table_backup_offset,
            reopened.superblock.file_table_offset,
            "обычный commit() должен был сохранить отдельный backup-offset, а не схлопнуть его как compact()"
        );
        reopened.close().unwrap();
        let _ = std::fs::remove_file(&path);
    }
}
