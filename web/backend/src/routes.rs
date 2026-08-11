//! HTTP-хендлеры библиотеки: список папки, поиск, папки, загрузка/скачивание,
//! удаление/восстановление, переименование/перемещение, избранное. Все —
//! кроме health и login — требуют `AuthedSession` (auth.rs: кука + CSRF для
//! не-GET методов).

use axum::extract::{Multipart, Path, Query};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use cove_core::container::FileId;
use cove_core::search::SearchQuery;
use cove_core::CoveError;
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::actor::{Command, FileEntryDto};
use crate::auth::AuthedSession;
use crate::error::ApiError;

/// Общий помощник: шлёт команду актору и ждёт ответ через oneshot, оборачивая
/// оба возможных отказа (актор пропал / вернул CoveError) в `ApiError`.
async fn ask<T>(
    tx: &std::sync::mpsc::Sender<Command>,
    make: impl FnOnce(oneshot::Sender<Result<T, CoveError>>) -> Command,
) -> Result<T, ApiError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(make(reply_tx))
        .map_err(|_| ApiError::Internal("session actor terminated"))?;
    reply_rx
        .await
        .map_err(|_| ApiError::Internal("session actor terminated"))?
        .map_err(ApiError::Core)
}

pub async fn me(session: AuthedSession) -> impl IntoResponse {
    #[derive(Serialize)]
    struct Me {
        username: String,
        role: String,
    }
    Json(Me {
        username: session.username,
        role: session.role,
    })
}

#[derive(Deserialize)]
pub struct FolderParam {
    #[serde(default)]
    folder_id: FileId,
}

pub async fn list_dir(
    session: AuthedSession,
    Query(params): Query<FolderParam>,
) -> Result<Json<Vec<FileEntryDto>>, ApiError> {
    let entries = ask(&session.tx, |reply| Command::ListDir {
        folder_id: params.folder_id,
        reply,
    })
    .await?;
    Ok(Json(entries))
}

pub async fn list_trash(session: AuthedSession) -> Result<Json<Vec<FileEntryDto>>, ApiError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    session
        .tx
        .send(Command::ListTrash { reply: reply_tx })
        .map_err(|_| ApiError::Internal("session actor terminated"))?;
    let entries = reply_rx
        .await
        .map_err(|_| ApiError::Internal("session actor terminated"))?;
    Ok(Json(entries))
}

#[derive(Deserialize)]
pub struct SearchParams {
    name_contains: Option<String>,
    extension: Option<String>,
    category: Option<String>,
    folder_id: Option<FileId>,
    min_size: Option<u64>,
    max_size: Option<u64>,
    modified_after: Option<u64>,
    modified_before: Option<u64>,
    favorite: Option<bool>,
}

pub async fn search(
    session: AuthedSession,
    Query(p): Query<SearchParams>,
) -> Result<Json<Vec<FileEntryDto>>, ApiError> {
    let query = SearchQuery {
        name_contains: p.name_contains,
        extension: p.extension,
        category: p.category,
        folder_id: p.folder_id,
        min_size: p.min_size,
        max_size: p.max_size,
        modified_after: p.modified_after,
        modified_before: p.modified_before,
        favorite: p.favorite,
    };
    let entries = ask(&session.tx, |reply| Command::Search { query, reply }).await?;
    Ok(Json(entries))
}

#[derive(Deserialize)]
pub struct CreateFolderRequest {
    name: String,
    #[serde(default)]
    parent_id: FileId,
    #[serde(default)]
    category: Option<String>,
}

pub async fn create_folder(
    session: AuthedSession,
    Json(body): Json<CreateFolderRequest>,
) -> Result<Json<FileId>, ApiError> {
    let id = ask(&session.tx, |reply| Command::CreateFolder {
        name: body.name,
        parent_id: body.parent_id,
        category: body.category,
        reply,
    })
    .await?;
    Ok(Json(id))
}

pub async fn upload(
    session: AuthedSession,
    mut multipart: Multipart,
) -> Result<Json<FileId>, ApiError> {
    let mut parent_id: FileId = 0;
    let mut name: Option<String> = None;
    let mut data: Option<Vec<u8>> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| ApiError::BadRequest("invalid multipart body".into()))?
    {
        match field.name().unwrap_or("") {
            "parent_id" => {
                let text = field
                    .text()
                    .await
                    .map_err(|_| ApiError::BadRequest("invalid parent_id field".into()))?;
                parent_id = text
                    .parse()
                    .map_err(|_| ApiError::BadRequest("parent_id must be a number".into()))?;
            }
            "file" => {
                name = field.file_name().map(|s| s.to_string());
                data = Some(
                    field
                        .bytes()
                        .await
                        .map_err(|_| ApiError::BadRequest("failed to read file field".into()))?
                        .to_vec(),
                );
            }
            _ => {}
        }
    }

    let name = name.ok_or_else(|| ApiError::BadRequest("missing file field".into()))?;
    let data = data.ok_or_else(|| ApiError::BadRequest("missing file field".into()))?;

    let id = ask(&session.tx, |reply| Command::Import {
        name,
        parent_id,
        data,
        reply,
    })
    .await?;
    Ok(Json(id))
}

fn guess_content_type(mime_hint: Option<&str>) -> String {
    mime_hint.unwrap_or("application/octet-stream").to_string()
}

/// Разбирает заголовок `Range: bytes=start-end` (только single-range,
/// достаточно для видео/аудио-плеера в браузере). `None` — заголовка не
/// было; `Some(Err(_))` — заголовок был, но некорректный.
fn parse_range(header: &str, size: u64) -> Option<Result<(u64, u64), ()>> {
    let spec = header.strip_prefix("bytes=")?;
    let (start_s, end_s) = spec.split_once('-')?;
    if start_s.is_empty() {
        return Some(Err(()));
    }
    let start: u64 = start_s.parse().map_err(|_| ()).ok()?;
    let end: u64 = if end_s.is_empty() {
        size.saturating_sub(1)
    } else {
        match end_s.parse() {
            Ok(v) => v,
            Err(_) => return Some(Err(())),
        }
    };
    if start > end || end >= size {
        return Some(Err(()));
    }
    Some(Ok((start, end)))
}

pub async fn download(
    session: AuthedSession,
    Path(file_id): Path<FileId>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    session
        .tx
        .send(Command::FileMeta {
            file_id,
            reply: reply_tx,
        })
        .map_err(|_| ApiError::Internal("session actor terminated"))?;
    let meta = reply_rx
        .await
        .map_err(|_| ApiError::Internal("session actor terminated"))?;
    let (size, mime_hint, name) = meta.ok_or(ApiError::Core(CoveError::NotFound))?;

    let range_header = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let content_type = guess_content_type(mime_hint.as_deref());
    let disposition = format!("inline; filename=\"{}\"", name.replace('"', "'"));

    if let Some(raw) = range_header {
        let (start, end) = match parse_range(&raw, size) {
            Some(Ok(r)) => r,
            _ => {
                return Ok((
                    StatusCode::RANGE_NOT_SATISFIABLE,
                    [(header::CONTENT_RANGE, format!("bytes */{size}"))],
                )
                    .into_response())
            }
        };
        let len = (end - start + 1) as u32;
        let bytes = ask(&session.tx, |reply| Command::ReadAt {
            file_id,
            offset: start,
            len,
            reply,
        })
        .await?;
        return Ok((
            StatusCode::PARTIAL_CONTENT,
            [
                (header::CONTENT_TYPE, content_type),
                (header::CONTENT_RANGE, format!("bytes {start}-{end}/{size}")),
                (header::ACCEPT_RANGES, "bytes".to_string()),
                (header::CONTENT_DISPOSITION, disposition),
            ],
            bytes,
        )
            .into_response());
    }

    if size > u32::MAX as u64 {
        return Err(ApiError::BadRequest(
            "file too large for a non-range download; request with a Range header".into(),
        ));
    }
    let bytes = ask(&session.tx, |reply| Command::ReadAt {
        file_id,
        offset: 0,
        len: size as u32,
        reply,
    })
    .await?;
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            (header::ACCEPT_RANGES, "bytes".to_string()),
            (header::CONTENT_DISPOSITION, disposition),
        ],
        bytes,
    )
        .into_response())
}

pub async fn delete(
    session: AuthedSession,
    Path(file_id): Path<FileId>,
) -> Result<StatusCode, ApiError> {
    ask(&session.tx, |reply| Command::Delete { file_id, reply }).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn restore(
    session: AuthedSession,
    Path(file_id): Path<FileId>,
) -> Result<StatusCode, ApiError> {
    ask(&session.tx, |reply| Command::Restore { file_id, reply }).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct RenameRequest {
    name: String,
}

pub async fn rename(
    session: AuthedSession,
    Path(file_id): Path<FileId>,
    Json(body): Json<RenameRequest>,
) -> Result<StatusCode, ApiError> {
    ask(&session.tx, |reply| Command::Rename {
        file_id,
        new_name: body.name,
        reply,
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct MoveRequest {
    parent_id: FileId,
}

pub async fn move_file(
    session: AuthedSession,
    Path(file_id): Path<FileId>,
    Json(body): Json<MoveRequest>,
) -> Result<StatusCode, ApiError> {
    ask(&session.tx, |reply| Command::Move {
        file_id,
        new_parent: body.parent_id,
        reply,
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct FavoriteRequest {
    favorite: bool,
}

pub async fn set_favorite(
    session: AuthedSession,
    Path(file_id): Path<FileId>,
    Json(body): Json<FavoriteRequest>,
) -> Result<StatusCode, ApiError> {
    ask(&session.tx, |reply| Command::SetFavorite {
        file_id,
        favorite: body.favorite,
        reply,
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}
