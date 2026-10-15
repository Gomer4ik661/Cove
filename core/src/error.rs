//! Единый тип ошибок Core. Категории и правила маппинга на границе FFI
//! зафиксированы в docs/ARCHITECTURE.md §3 — не добавлять новые категории
//! без обновления того документа и всех биндингов.

use std::fmt;

#[derive(Debug, thiserror::Error)]
pub enum CoveError {
    /// Неверный пароль ИЛИ несуществующий пользователь — намеренно одна и
    /// та же ошибка, чтобы не давать enumerate пользователей по ответу.
    #[error("authentication failed")]
    AuthFailed,

    /// Повреждённая структура контейнера. `detail` — только для логов
    /// на стороне разработчика, никогда не должен уходить в UI/HTTP как есть.
    #[error("container format error")]
    FormatError { detail: String },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("not found")]
    NotFound,

    #[error("already exists")]
    AlreadyExists,

    #[error("permission denied")]
    PermissionDenied,

    /// На диске уже другая версия, чем та, с которой синхронизирована эта
    /// сессия — кто-то ещё (другая одновременно открытая сессия того же
    /// контейнера) закоммитил изменения первым. Введено по прямому запросу
    /// пользователя после реального случая потери данных: сессия A создала
    /// папку и закоммитила, но позже сессия B (открытая раньше, с устаревшим
    /// File Table в памяти) закрылась и молча перезаписала диск своей
    /// версией без папки. Раньше `commit()`/`close()` писали безусловно —
    /// теперь при обнаружении чужой более новой версии коммит отклоняется
    /// вместо того, чтобы тихо затереть чужие изменения (THREAT_MODEL.md —
    /// сознательный компромисс уже задокументирован как риск, но раньше
    /// проявлялся только на `close()`; commit() посреди сессии сделал его
    /// НАМНОГО вероятнее).
    #[error("stale session: on-disk version has moved since last sync")]
    Conflict,
}

/// Публичная категория ошибки без деталей — то, что безопасно показывать
/// пользователю или отдавать в HTTP-ответе (ARCHITECTURE.md §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    AuthFailed,
    FormatError,
    Io,
    NotFound,
    AlreadyExists,
    PermissionDenied,
    Conflict,
}

impl fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ErrorCategory::AuthFailed => "auth_failed",
            ErrorCategory::FormatError => "format_error",
            ErrorCategory::Io => "io",
            ErrorCategory::NotFound => "not_found",
            ErrorCategory::AlreadyExists => "already_exists",
            ErrorCategory::PermissionDenied => "permission_denied",
            ErrorCategory::Conflict => "conflict",
        };
        f.write_str(s)
    }
}

impl CoveError {
    pub fn category(&self) -> ErrorCategory {
        match self {
            CoveError::AuthFailed => ErrorCategory::AuthFailed,
            CoveError::FormatError { .. } => ErrorCategory::FormatError,
            CoveError::Io(_) => ErrorCategory::Io,
            CoveError::NotFound => ErrorCategory::NotFound,
            CoveError::AlreadyExists => ErrorCategory::AlreadyExists,
            CoveError::PermissionDenied => ErrorCategory::PermissionDenied,
            CoveError::Conflict => ErrorCategory::Conflict,
        }
    }
}

pub type Result<T> = std::result::Result<T, CoveError>;
