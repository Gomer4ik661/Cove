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

        let file_table = read_file_table(&mut file, &sb, &dek)?;
        let free_blocks = read_free_map(&mut file, &sb, &dek)?;
        let mut log = read_login_log(&mut file, &sb, &dek)?;
        log.push(LoginLogEntry {
            username: identity.to_string(),
            timestamp: now_unix(),
            success: true,
        });

        let next_file_id = file_table.iter().map(|e| e.file_id).max().map(|m| m + 1).unwrap_or(1);

        Ok(Container {
            path: self.path.clone(),
            header: self.header,
            session: Session { dek },
            superblock: sb,
            file_table,
            free_blocks,
            keyslots: self.keyslots.clone(),
            login_log: log,
            current_username: identity.to_string(),
            current_role: role,
            next_file_id,
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
        self.file_table
            .retain(|e| !(e.flags.internal && e.thumbnail_of == Some(file_id)));
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

        if let Some(entry) = self.file_table.iter_mut().find(|e| e.file_id == thumb_id) {
            entry.block_list = block_list;
            entry.size = size;
            entry.content_hash = content_hash;
            entry.modified_at = now;
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
            });
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
        });
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
        });
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
        let entry = self
            .file_table
            .iter_mut()
            .find(|e| e.file_id == file_id)
            .unwrap();
        entry.block_list = block_list;
        entry.size = size;
        entry.content_hash = content_hash;
        entry.modified_at = now_unix();
        // Содержимое изменилось — старая миниатюра больше не соответствует
        // файлу; следующий вызов thumbnail() честно перегенерирует её
        // (ROADMAP.md Фаза 8: "автообновление").
        self.remove_thumbnail_of(file_id);
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

    pub fn create_folder(&mut self, name: &str, parent_id: FileId) -> Result<FileId> {
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
        });
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
        } else {
            let entry = self.file_table.iter_mut().find(|e| e.file_id == file_id).unwrap();
            entry.flags.trashed = true;
            entry.modified_at = now_unix();
        }
        Ok(())
    }

    pub fn restore_file(&mut self, file_id: FileId) -> Result<()> {
        self.require_writable()?;
        let entry = self
            .file_table
            .iter_mut()
            .find(|e| e.file_id == file_id)
            .ok_or(CoveError::NotFound)?;
        entry.flags.trashed = false;
        entry.modified_at = now_unix();
        Ok(())
    }

    pub fn rename_file(&mut self, file_id: FileId, new_name: &str) -> Result<()> {
        self.require_writable()?;
        if new_name.is_empty() {
            return Err(CoveError::FormatError {
                detail: "name must not be empty".into(),
            });
        }
        let entry = self
            .file_table
            .iter_mut()
            .find(|e| e.file_id == file_id)
            .ok_or(CoveError::NotFound)?;
        entry.name = new_name.to_string();
        entry.modified_at = now_unix();
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
        let entry = self
            .file_table
            .iter_mut()
            .find(|e| e.file_id == file_id)
            .ok_or(CoveError::NotFound)?;
        entry.parent_id = new_parent;
        entry.modified_at = now_unix();
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
        let entry = self
            .file_table
            .iter_mut()
            .find(|e| e.file_id == file_id)
            .ok_or(CoveError::NotFound)?;
        entry.flags.favorite = favorite;
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
    pub fn close(self) -> Result<()> {
        let mut file = OpenOptions::new().read(true).write(true).open(&self.path)?;

        let (current_pointer, active_offset) =
            read_valid_commit_pointer(&mut file, &self.header)?;
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

        let file_table_bytes = file_table::encode_file_table(&self.file_table, &self.session.dek);
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

        Ok(())
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

fn read_file_table(file: &mut File, sb: &Superblock, dek: &keys::Dek) -> Result<Vec<FileEntry>> {
    file.seek(SeekFrom::Start(sb.file_table_offset))?;
    let mut buf = vec![0u8; sb.file_table_len as usize];
    file.read_exact(&mut buf)?;
    file_table::decode_file_table(&buf, dek)
}

fn read_free_map(file: &mut File, sb: &Superblock, dek: &keys::Dek) -> Result<Vec<u64>> {
    file.seek(SeekFrom::Start(sb.free_block_map_offset))?;
    let mut buf = vec![0u8; sb.free_block_map_len as usize];
    file.read_exact(&mut buf)?;
    free_map::decode(&buf, dek)
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

        let folder_id = c.create_folder("Фото", ROOT_FOLDER_ID).unwrap();
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
            viewer.create_folder("x", ROOT_FOLDER_ID),
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

        let outer = c.create_folder("Снаружи", ROOT_FOLDER_ID).unwrap();
        let inner = c.create_folder("Внутри", outer).unwrap();
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

        let outer = c.create_folder("Outer", ROOT_FOLDER_ID).unwrap();
        let inner = c.create_folder("Inner", outer).unwrap();

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
}
