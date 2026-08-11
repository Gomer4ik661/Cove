//! UniFFI-биндинги над cove-core для Kotlin/Android (Фаза 14, ROADMAP.md).
//! Proc-macro режим (без .udl файла) — ARCHITECTURE.md §1. Правила
//! маппинга ошибок такие же, как у PyO3-биндингов (ARCHITECTURE.md §3):
//! категория `CoveError` → отдельный вариант `AndroidError`, без внутренних
//! деталей (сырых путей/оффсетов) в тексте, который дойдёт до Kotlin.
//!
//! `Container`/`LockedContainer` из core сами по себе не подходят под то,
//! что нужно UniFFI Object-типам (клиент получает `Arc<T>`, методы могут
//! вызываться из разных Kotlin-корутин) — оборачиваем в `Mutex`, аналогично
//! тому, как PyO3-биндинги полагаются на GIL для той же цели.

use std::sync::Arc;
use std::sync::Mutex;

use cove_core::error::ErrorCategory;
use cove_core::format::file_table::FileEntry as CoreFileEntry;
use cove_core::format::keyslots::Role as CoreRole;
use cove_core::search::SearchQuery as CoreSearchQuery;
use cove_core::users::LoginLogEntry as CoreLoginLogEntry;
use cove_core::{Container as CoreContainer, LockedContainer as CoreLockedContainer};

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum AndroidError {
    #[error("authentication failed")]
    AuthFailed,
    #[error("container format error")]
    FormatError,
    #[error("io error")]
    Io,
    #[error("not found")]
    NotFound,
    #[error("already exists")]
    AlreadyExists,
    #[error("permission denied")]
    PermissionDenied,
    #[error("container already closed")]
    Closed,
}

impl From<cove_core::CoveError> for AndroidError {
    fn from(e: cove_core::CoveError) -> Self {
        match e.category() {
            ErrorCategory::AuthFailed => AndroidError::AuthFailed,
            ErrorCategory::FormatError => AndroidError::FormatError,
            ErrorCategory::Io => AndroidError::Io,
            ErrorCategory::NotFound => AndroidError::NotFound,
            ErrorCategory::AlreadyExists => AndroidError::AlreadyExists,
            ErrorCategory::PermissionDenied => AndroidError::PermissionDenied,
        }
    }
}

#[derive(uniffi::Enum, Clone, Copy)]
pub enum Role {
    Admin,
    ReadWrite,
    ReadOnly,
}

impl From<CoreRole> for Role {
    fn from(r: CoreRole) -> Self {
        match r {
            CoreRole::Admin => Role::Admin,
            CoreRole::ReadWrite => Role::ReadWrite,
            CoreRole::ReadOnly => Role::ReadOnly,
        }
    }
}

impl From<Role> for CoreRole {
    fn from(r: Role) -> Self {
        match r {
            Role::Admin => CoreRole::Admin,
            Role::ReadWrite => CoreRole::ReadWrite,
            Role::ReadOnly => CoreRole::ReadOnly,
        }
    }
}

#[derive(uniffi::Record)]
pub struct FileEntry {
    pub file_id: u64,
    pub parent_id: u64,
    pub name: String,
    pub size: u64,
    pub created_at: u64,
    pub modified_at: u64,
    pub mime_hint: Option<String>,
    pub trashed: bool,
    pub favorite: bool,
    pub is_folder: bool,
    pub folder_category: Option<String>,
}

impl From<CoreFileEntry> for FileEntry {
    fn from(e: CoreFileEntry) -> Self {
        FileEntry {
            file_id: e.file_id,
            parent_id: e.parent_id,
            name: e.name,
            size: e.size,
            created_at: e.created_at,
            modified_at: e.modified_at,
            mime_hint: e.mime_hint,
            trashed: e.flags.trashed,
            favorite: e.flags.favorite,
            is_folder: e.flags.is_folder,
            folder_category: e.folder_category,
        }
    }
}

#[derive(uniffi::Record)]
pub struct LoginLogEntry {
    pub username: String,
    pub timestamp: u64,
    pub success: bool,
}

impl From<CoreLoginLogEntry> for LoginLogEntry {
    fn from(e: CoreLoginLogEntry) -> Self {
        LoginLogEntry {
            username: e.username,
            timestamp: e.timestamp,
            success: e.success,
        }
    }
}

#[derive(uniffi::Record)]
pub struct SearchQuery {
    #[uniffi(default = None)]
    pub name_contains: Option<String>,
    #[uniffi(default = None)]
    pub extension: Option<String>,
    #[uniffi(default = None)]
    pub category: Option<String>,
    #[uniffi(default = None)]
    pub folder_id: Option<u64>,
    #[uniffi(default = None)]
    pub min_size: Option<u64>,
    #[uniffi(default = None)]
    pub max_size: Option<u64>,
    #[uniffi(default = None)]
    pub modified_after: Option<u64>,
    #[uniffi(default = None)]
    pub modified_before: Option<u64>,
    #[uniffi(default = None)]
    pub favorite: Option<bool>,
}

impl From<SearchQuery> for CoreSearchQuery {
    fn from(q: SearchQuery) -> Self {
        CoreSearchQuery {
            name_contains: q.name_contains,
            extension: q.extension,
            category: q.category,
            folder_id: q.folder_id,
            min_size: q.min_size,
            max_size: q.max_size,
            modified_after: q.modified_after,
            modified_before: q.modified_before,
            favorite: q.favorite,
        }
    }
}

#[derive(uniffi::Record)]
pub struct UserEntry {
    pub username: String,
    pub role: Role,
}

#[derive(uniffi::Record)]
pub struct CreateResult {
    pub container: Arc<AndroidContainer>,
    pub recovery_phrase: String,
}

/// Смоук-тест: проверить, что биндинг собирается и генерирует Kotlin.
#[uniffi::export]
fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[uniffi::export]
fn create_container(
    path: String,
    admin_username: String,
    admin_password: String,
) -> Result<CreateResult, AndroidError> {
    let (container, recovery) = CoreContainer::create(&path, &admin_username, &admin_password)?;
    Ok(CreateResult {
        container: Arc::new(AndroidContainer {
            inner: Mutex::new(Some(container)),
        }),
        recovery_phrase: recovery.0,
    })
}

#[derive(uniffi::Object)]
pub struct AndroidLockedContainer {
    inner: CoreLockedContainer,
}

#[uniffi::export]
impl AndroidLockedContainer {
    #[uniffi::constructor]
    fn open(path: String) -> Result<Self, AndroidError> {
        Ok(AndroidLockedContainer {
            inner: CoreLockedContainer::open(&path)?,
        })
    }

    fn list_usernames(&self) -> Vec<String> {
        self.inner.list_usernames()
    }

    fn unlock(&self, username: String, password: String) -> Result<Arc<AndroidContainer>, AndroidError> {
        let c = self.inner.unlock(&username, &password)?;
        Ok(Arc::new(AndroidContainer {
            inner: Mutex::new(Some(c)),
        }))
    }

    fn unlock_with_recovery(&self, phrase: String) -> Result<Arc<AndroidContainer>, AndroidError> {
        let c = self.inner.unlock_with_recovery(&phrase)?;
        Ok(Arc::new(AndroidContainer {
            inner: Mutex::new(Some(c)),
        }))
    }
}

/// Разблокированная сессия. `inner` — `Mutex<Option<_>>`: `Option`, потому
/// что `close()` потребляет `cove_core::Container` (владение), `Mutex` —
/// потому что UniFFI Object раздаётся клиенту как `Arc<Self>` и вызывается
/// через `&self` из корутин, а не эксклюзивно из одного потока, как в PyO3.
#[derive(uniffi::Object)]
pub struct AndroidContainer {
    inner: Mutex<Option<CoreContainer>>,
}

impl AndroidContainer {
    fn with<T>(
        &self,
        f: impl FnOnce(&CoreContainer) -> Result<T, cove_core::CoveError>,
    ) -> Result<T, AndroidError> {
        let guard = self.inner.lock().unwrap();
        let c = guard.as_ref().ok_or(AndroidError::Closed)?;
        Ok(f(c)?)
    }

    fn with_mut<T>(
        &self,
        f: impl FnOnce(&mut CoreContainer) -> Result<T, cove_core::CoveError>,
    ) -> Result<T, AndroidError> {
        let mut guard = self.inner.lock().unwrap();
        let c = guard.as_mut().ok_or(AndroidError::Closed)?;
        Ok(f(c)?)
    }
}

#[uniffi::export]
impl AndroidContainer {
    fn add_user(&self, username: String, password: String, role: Role) -> Result<(), AndroidError> {
        self.with_mut(|c| c.add_user(&username, &password, role.into()))
    }

    fn remove_user(&self, username: String) -> Result<(), AndroidError> {
        self.with_mut(|c| c.remove_user(&username))
    }

    /// Активные пользователи — без recovery-слота.
    fn list_users(&self) -> Result<Vec<UserEntry>, AndroidError> {
        self.with(|c| {
            Ok(c.list_users()
                .into_iter()
                .map(|(username, role)| UserEntry {
                    username,
                    role: Role::from(role),
                })
                .collect())
        })
    }

    fn set_user_role(&self, username: String, role: Role) -> Result<(), AndroidError> {
        self.with_mut(|c| c.set_user_role(&username, role.into()))
    }

    fn change_password(&self, username: String, old: String, new: String) -> Result<(), AndroidError> {
        self.with_mut(|c| c.change_password(&username, &old, &new))
    }

    fn list_dir(&self, folder_id: u64) -> Result<Vec<FileEntry>, AndroidError> {
        self.with(|c| {
            Ok(c.list_dir(folder_id)?
                .into_iter()
                .map(FileEntry::from)
                .collect())
        })
    }

    fn list_trash(&self) -> Result<Vec<FileEntry>, AndroidError> {
        self.with(|c| Ok(c.list_trash().into_iter().map(FileEntry::from).collect()))
    }

    fn search(&self, query: SearchQuery) -> Result<Vec<FileEntry>, AndroidError> {
        self.with(|c| {
            Ok(c.search(query.into())?
                .into_iter()
                .map(FileEntry::from)
                .collect())
        })
    }

    fn set_favorite(&self, file_id: u64, favorite: bool) -> Result<(), AndroidError> {
        self.with_mut(|c| c.set_favorite(file_id, favorite))
    }

    fn import_file(&self, src_path: String, parent_id: u64) -> Result<u64, AndroidError> {
        self.with_mut(|c| c.import_file(&src_path, parent_id))
    }

    /// Импорт из байтов уже в памяти — нужен на Android, где SAF
    /// (Storage Access Framework) отдаёт `content://`-дескрипторы, а не
    /// пути файловой системы, доступные обычному `File::open`.
    fn import_file_from_bytes(&self, name: String, parent_id: u64, data: Vec<u8>) -> Result<u64, AndroidError> {
        self.with_mut(|c| c.import_file_from_bytes(&name, parent_id, &data))
    }

    fn replace_file_content(&self, file_id: u64, src_path: String) -> Result<(), AndroidError> {
        self.with_mut(|c| c.replace_file_content(file_id, &src_path))
    }

    fn export_file(&self, file_id: u64, dest_path: String) -> Result<(), AndroidError> {
        self.with(|c| c.export_file(file_id, &dest_path))
    }

    fn create_folder(
        &self,
        name: String,
        parent_id: u64,
        category: Option<String>,
    ) -> Result<u64, AndroidError> {
        self.with_mut(|c| c.create_folder(&name, parent_id, category.as_deref()))
    }

    fn delete_file(&self, file_id: u64) -> Result<(), AndroidError> {
        self.with_mut(|c| c.delete_file(file_id))
    }

    fn restore_file(&self, file_id: u64) -> Result<(), AndroidError> {
        self.with_mut(|c| c.restore_file(file_id))
    }

    fn rename_file(&self, file_id: u64, new_name: String) -> Result<(), AndroidError> {
        self.with_mut(|c| c.rename_file(file_id, &new_name))
    }

    fn move_file(&self, file_id: u64, new_parent: u64) -> Result<(), AndroidError> {
        self.with_mut(|c| c.move_file(file_id, new_parent))
    }

    fn file_size(&self, file_id: u64) -> Result<u64, AndroidError> {
        self.with(|c| c.file_size(file_id))
    }

    fn read_at(&self, file_id: u64, offset: u64, len: u32) -> Result<Vec<u8>, AndroidError> {
        self.with(|c| c.read_at(file_id, offset, len))
    }

    /// `thumbnail_data` — уже готовые байты (decode+resize делает
    /// Kotlin-сторона через `BitmapFactory`, аналогично тому, как это
    /// делает Qt на десктопе — см. docs/ARCHITECTURE.md). Возвращает
    /// `file_id` миниатюры.
    fn thumbnail(&self, file_id: u64, thumbnail_data: Vec<u8>) -> Result<u64, AndroidError> {
        self.with_mut(|c| c.thumbnail(file_id, &thumbnail_data))
    }

    fn find_thumbnail(&self, file_id: u64) -> Result<Option<u64>, AndroidError> {
        self.with(|c| Ok(c.find_thumbnail(file_id)))
    }

    fn login_history(&self) -> Result<Vec<LoginLogEntry>, AndroidError> {
        self.with(|c| {
            Ok(c.login_history()
                .iter()
                .cloned()
                .map(LoginLogEntry::from)
                .collect())
        })
    }

    fn current_username(&self) -> Result<String, AndroidError> {
        self.with(|c| Ok(c.current_username().to_string()))
    }

    fn current_role(&self) -> Result<Role, AndroidError> {
        self.with(|c| Ok(Role::from(c.current_role())))
    }

    /// Названо `close_container`, а не `close` — UniFFI сам генерирует
    /// `close()`/`AutoCloseable` для Object-типов (освобождение handle), и
    /// одноимённый экспортированный метод конфликтовал с ним на Kotlin-
    /// стороне ("Conflicting overloads"). Идемпотентно: повторный вызов
    /// после закрытия — no-op, а не ошибка, чтобы UI не нужно было
    /// отслеживать, звал ли он close_container() раньше.
    fn close_container(&self) -> Result<(), AndroidError> {
        let mut guard = self.inner.lock().unwrap();
        match guard.take() {
            Some(c) => Ok(c.close()?),
            None => Ok(()),
        }
    }
}
