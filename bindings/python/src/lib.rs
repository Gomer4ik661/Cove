//! PyO3-биндинги над cove-core. Правила маппинга ошибок — ARCHITECTURE.md §3:
//! категория CoveError → отдельный Python-класс исключения, без внутренних
//! деталей вроде сырых путей/оффсетов в тексте. Через границу — только
//! простые типы (строки/числа/векторы), как требует ARCHITECTURE.md §2.

use cove_core::error::ErrorCategory;
use cove_core::format::file_table::FileEntry as CoreFileEntry;
use cove_core::format::keyslots::Role as CoreRole;
use cove_core::search::SearchQuery as CoreSearchQuery;
use cove_core::users::LoginLogEntry as CoreLoginLogEntry;
use cove_core::{Container as CoreContainer, LockedContainer as CoreLockedContainer};
use pyo3::exceptions::{PyException, PyValueError};
use pyo3::prelude::*;

pyo3::create_exception!(cove_core_py, CoveAuthError, PyException);
pyo3::create_exception!(cove_core_py, CoveFormatError, PyException);
pyo3::create_exception!(cove_core_py, CoveIoError, PyException);
pyo3::create_exception!(cove_core_py, CoveNotFoundError, PyException);
pyo3::create_exception!(cove_core_py, CoveAlreadyExistsError, PyException);
pyo3::create_exception!(cove_core_py, CovePermissionError, PyException);

fn to_py_err(e: cove_core::CoveError) -> PyErr {
    let msg = e.to_string();
    match e.category() {
        ErrorCategory::AuthFailed => CoveAuthError::new_err(msg),
        ErrorCategory::FormatError => CoveFormatError::new_err(msg),
        ErrorCategory::Io => CoveIoError::new_err(msg),
        ErrorCategory::NotFound => CoveNotFoundError::new_err(msg),
        ErrorCategory::AlreadyExists => CoveAlreadyExistsError::new_err(msg),
        ErrorCategory::PermissionDenied => CovePermissionError::new_err(msg),
    }
}

fn role_from_str(s: &str) -> PyResult<CoreRole> {
    match s {
        "admin" => Ok(CoreRole::Admin),
        "read_write" => Ok(CoreRole::ReadWrite),
        "read_only" => Ok(CoreRole::ReadOnly),
        other => Err(PyValueError::new_err(format!(
            "unknown role '{other}', expected admin/read_write/read_only"
        ))),
    }
}

fn role_to_str(r: CoreRole) -> &'static str {
    match r {
        CoreRole::Admin => "admin",
        CoreRole::ReadWrite => "read_write",
        CoreRole::ReadOnly => "read_only",
    }
}

/// Смоук-тест: проверить, что биндинг собирается и импортируется из Python.
#[pyfunction]
fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[pyclass(name = "FileEntry")]
struct PyFileEntry {
    #[pyo3(get)]
    file_id: u64,
    #[pyo3(get)]
    parent_id: u64,
    #[pyo3(get)]
    name: String,
    #[pyo3(get)]
    size: u64,
    #[pyo3(get)]
    created_at: u64,
    #[pyo3(get)]
    modified_at: u64,
    #[pyo3(get)]
    mime_hint: Option<String>,
    #[pyo3(get)]
    trashed: bool,
    #[pyo3(get)]
    favorite: bool,
    #[pyo3(get)]
    is_folder: bool,
    #[pyo3(get)]
    folder_category: Option<String>,
}

impl From<CoreFileEntry> for PyFileEntry {
    fn from(e: CoreFileEntry) -> Self {
        PyFileEntry {
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

#[pyclass(name = "LoginLogEntry")]
struct PyLoginLogEntry {
    #[pyo3(get)]
    username: String,
    #[pyo3(get)]
    timestamp: u64,
    #[pyo3(get)]
    success: bool,
}

impl From<CoreLoginLogEntry> for PyLoginLogEntry {
    fn from(e: CoreLoginLogEntry) -> Self {
        PyLoginLogEntry {
            username: e.username,
            timestamp: e.timestamp,
            success: e.success,
        }
    }
}

/// Разблокированная сессия. `inner` — `Option`, потому что `close()`
/// потребляет `cove_core::Container` (владение), а из Python методы вызываются
/// по `&mut self` — `.take()` в `close()` мимикрирует переход владения.
#[pyclass(name = "Container")]
struct PyContainer {
    inner: Option<CoreContainer>,
}

impl PyContainer {
    fn get(&self) -> PyResult<&CoreContainer> {
        self.inner
            .as_ref()
            .ok_or_else(|| CoveIoError::new_err("container already closed"))
    }

    fn get_mut(&mut self) -> PyResult<&mut CoreContainer> {
        self.inner
            .as_mut()
            .ok_or_else(|| CoveIoError::new_err("container already closed"))
    }
}

#[pymethods]
impl PyContainer {
    #[staticmethod]
    fn create(path: &str, admin_username: &str, admin_password: &str) -> PyResult<(PyContainer, String)> {
        let (container, recovery) =
            CoreContainer::create(path, admin_username, admin_password).map_err(to_py_err)?;
        Ok((
            PyContainer {
                inner: Some(container),
            },
            recovery.0,
        ))
    }

    fn add_user(&mut self, username: &str, password: &str, role: &str) -> PyResult<()> {
        let role = role_from_str(role)?;
        self.get_mut()?
            .add_user(username, password, role)
            .map_err(to_py_err)
    }

    fn remove_user(&mut self, username: &str) -> PyResult<()> {
        self.get_mut()?.remove_user(username).map_err(to_py_err)
    }

    /// Список (username, role) активных пользователей — без recovery-слота.
    fn list_users(&self) -> PyResult<Vec<(String, &'static str)>> {
        Ok(self
            .get()?
            .list_users()
            .into_iter()
            .map(|(username, role)| (username, role_to_str(role)))
            .collect())
    }

    fn set_user_role(&mut self, username: &str, role: &str) -> PyResult<()> {
        let role = role_from_str(role)?;
        self.get_mut()?
            .set_user_role(username, role)
            .map_err(to_py_err)
    }

    fn change_password(&mut self, username: &str, old: &str, new: &str) -> PyResult<()> {
        self.get_mut()?
            .change_password(username, old, new)
            .map_err(to_py_err)
    }

    #[pyo3(signature = (folder_id=0))]
    fn list_dir(&self, folder_id: u64) -> PyResult<Vec<PyFileEntry>> {
        let entries = self.get()?.list_dir(folder_id).map_err(to_py_err)?;
        Ok(entries.into_iter().map(PyFileEntry::from).collect())
    }

    fn list_trash(&self) -> PyResult<Vec<PyFileEntry>> {
        Ok(self
            .get()?
            .list_trash()
            .into_iter()
            .map(PyFileEntry::from)
            .collect())
    }

    /// Все параметры опциональны — заданы только те критерии, что передали
    /// из Python (см. cove_core::search::SearchQuery).
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (
        name_contains=None, extension=None, category=None, folder_id=None,
        min_size=None, max_size=None, modified_after=None, modified_before=None,
        favorite=None
    ))]
    fn search(
        &self,
        name_contains: Option<String>,
        extension: Option<String>,
        category: Option<String>,
        folder_id: Option<u64>,
        min_size: Option<u64>,
        max_size: Option<u64>,
        modified_after: Option<u64>,
        modified_before: Option<u64>,
        favorite: Option<bool>,
    ) -> PyResult<Vec<PyFileEntry>> {
        let query = CoreSearchQuery {
            name_contains,
            extension,
            category,
            folder_id,
            min_size,
            max_size,
            modified_after,
            modified_before,
            favorite,
        };
        let entries = self.get()?.search(query).map_err(to_py_err)?;
        Ok(entries.into_iter().map(PyFileEntry::from).collect())
    }

    fn set_favorite(&mut self, file_id: u64, favorite: bool) -> PyResult<()> {
        self.get_mut()?.set_favorite(file_id, favorite).map_err(to_py_err)
    }

    #[pyo3(signature = (src_path, parent_id=0))]
    fn import_file(&mut self, src_path: &str, parent_id: u64) -> PyResult<u64> {
        self.get_mut()?
            .import_file(src_path, parent_id)
            .map_err(to_py_err)
    }

    fn replace_file_content(&mut self, file_id: u64, src_path: &str) -> PyResult<()> {
        self.get_mut()?
            .replace_file_content(file_id, src_path)
            .map_err(to_py_err)
    }

    fn export_file(&self, file_id: u64, dest_path: &str) -> PyResult<()> {
        self.get()?.export_file(file_id, dest_path).map_err(to_py_err)
    }

    #[pyo3(signature = (name, parent_id=0, category=None))]
    fn create_folder(&mut self, name: &str, parent_id: u64, category: Option<&str>) -> PyResult<u64> {
        self.get_mut()?
            .create_folder(name, parent_id, category)
            .map_err(to_py_err)
    }

    fn delete_file(&mut self, file_id: u64) -> PyResult<()> {
        self.get_mut()?.delete_file(file_id).map_err(to_py_err)
    }

    fn restore_file(&mut self, file_id: u64) -> PyResult<()> {
        self.get_mut()?.restore_file(file_id).map_err(to_py_err)
    }

    fn rename_file(&mut self, file_id: u64, new_name: &str) -> PyResult<()> {
        self.get_mut()?
            .rename_file(file_id, new_name)
            .map_err(to_py_err)
    }

    fn move_file(&mut self, file_id: u64, new_parent: u64) -> PyResult<()> {
        self.get_mut()?
            .move_file(file_id, new_parent)
            .map_err(to_py_err)
    }

    fn file_size(&self, file_id: u64) -> PyResult<u64> {
        self.get()?.file_size(file_id).map_err(to_py_err)
    }

    fn read_at(&self, file_id: u64, offset: u64, len: u32) -> PyResult<Vec<u8>> {
        self.get()?.read_at(file_id, offset, len).map_err(to_py_err)
    }

    /// `thumbnail_data` — уже готовые байты (decode+resize делает GUI, см.
    /// docs/ARCHITECTURE.md — Core не тянет свой декодер изображений там,
    /// где Qt уже умеет это на стороне GUI). Возвращает `file_id` миниатюры.
    fn thumbnail(&mut self, file_id: u64, thumbnail_data: &[u8]) -> PyResult<u64> {
        self.get_mut()?
            .thumbnail(file_id, thumbnail_data)
            .map_err(to_py_err)
    }

    fn find_thumbnail(&self, file_id: u64) -> PyResult<Option<u64>> {
        Ok(self.get()?.find_thumbnail(file_id))
    }

    fn login_history(&self) -> PyResult<Vec<PyLoginLogEntry>> {
        Ok(self
            .get()?
            .login_history()
            .iter()
            .cloned()
            .map(PyLoginLogEntry::from)
            .collect())
    }

    fn current_username(&self) -> PyResult<String> {
        Ok(self.get()?.current_username().to_string())
    }

    fn current_role(&self) -> PyResult<&'static str> {
        Ok(role_to_str(self.get()?.current_role()))
    }

    /// Идемпотентно: повторный вызов после закрытия — no-op, а не ошибка,
    /// чтобы GUI не нужно было отслеживать, звал ли он close() раньше
    /// (например, в обработчике и "Выйти", и закрытия окна).
    fn close(&mut self) -> PyResult<()> {
        match self.inner.take() {
            Some(c) => c.close().map_err(to_py_err),
            None => Ok(()),
        }
    }
}

#[pyclass(name = "LockedContainer")]
struct PyLockedContainer {
    inner: CoreLockedContainer,
}

#[pymethods]
impl PyLockedContainer {
    #[staticmethod]
    fn open(path: &str) -> PyResult<Self> {
        Ok(PyLockedContainer {
            inner: CoreLockedContainer::open(path).map_err(to_py_err)?,
        })
    }

    fn list_usernames(&self) -> Vec<String> {
        self.inner.list_usernames()
    }

    fn unlock(&self, username: &str, password: &str) -> PyResult<PyContainer> {
        let c = self.inner.unlock(username, password).map_err(to_py_err)?;
        Ok(PyContainer { inner: Some(c) })
    }

    fn unlock_with_recovery(&self, phrase: &str) -> PyResult<PyContainer> {
        let c = self
            .inner
            .unlock_with_recovery(phrase)
            .map_err(to_py_err)?;
        Ok(PyContainer { inner: Some(c) })
    }
}

#[pymodule]
fn cove_core_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(core_version, m)?)?;
    m.add_class::<PyContainer>()?;
    m.add_class::<PyLockedContainer>()?;
    m.add_class::<PyFileEntry>()?;
    m.add_class::<PyLoginLogEntry>()?;
    m.add("CoveAuthError", m.py().get_type::<CoveAuthError>())?;
    m.add("CoveFormatError", m.py().get_type::<CoveFormatError>())?;
    m.add("CoveIoError", m.py().get_type::<CoveIoError>())?;
    m.add("CoveNotFoundError", m.py().get_type::<CoveNotFoundError>())?;
    m.add(
        "CoveAlreadyExistsError",
        m.py().get_type::<CoveAlreadyExistsError>(),
    )?;
    m.add("CovePermissionError", m.py().get_type::<CovePermissionError>())?;
    Ok(())
}
