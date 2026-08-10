//! Session-актор — ARCHITECTURE.md §4: каждый залогиненный пользователь
//! получает свой `Container`, живущий в отдельном выделенном потоке. HTTP-
//! хендлеры никогда не трогают `Container` напрямую — только шлют команды
//! через канал и ждут ответ через `oneshot`. Это даёт две вещи разом:
//! Container (и расшифрованный DEK внутри него) не пересекает границы
//! async-задач/пулов потоков tokio, и нам не нужно думать о Send/Sync для
//! него — он никогда не покидает свой поток.

use cove_core::container::{Container, FileId};
use cove_core::search::SearchQuery;
use cove_core::CoveError;
use serde::Serialize;
use tokio::sync::oneshot;

#[derive(Serialize, Clone)]
pub struct FileEntryDto {
    pub file_id: FileId,
    pub parent_id: FileId,
    pub name: String,
    pub size: u64,
    pub created_at: u64,
    pub modified_at: u64,
    pub mime_hint: Option<String>,
    pub is_folder: bool,
    pub favorite: bool,
    pub trashed: bool,
}

impl From<&cove_core::format::file_table::FileEntry> for FileEntryDto {
    fn from(e: &cove_core::format::file_table::FileEntry) -> Self {
        FileEntryDto {
            file_id: e.file_id,
            parent_id: e.parent_id,
            name: e.name.clone(),
            size: e.size,
            created_at: e.created_at,
            modified_at: e.modified_at,
            mime_hint: e.mime_hint.clone(),
            is_folder: e.flags.is_folder,
            favorite: e.flags.favorite,
            trashed: e.flags.trashed,
        }
    }
}

pub type Reply<T> = oneshot::Sender<Result<T, CoveError>>;

pub enum Command {
    ListDir {
        folder_id: FileId,
        reply: Reply<Vec<FileEntryDto>>,
    },
    ListTrash {
        reply: oneshot::Sender<Vec<FileEntryDto>>,
    },
    Search {
        query: SearchQuery,
        reply: Reply<Vec<FileEntryDto>>,
    },
    CreateFolder {
        name: String,
        parent_id: FileId,
        reply: Reply<FileId>,
    },
    Import {
        name: String,
        parent_id: FileId,
        data: Vec<u8>,
        reply: Reply<FileId>,
    },
    /// Размер + MIME-подсказка + имя — нужны хендлеру скачивания сразу все
    /// вместе (Content-Length/Content-Type/Content-Disposition). Публичного
    /// "получить запись по id" в Container нет, поэтому идём через search()
    /// с пустым фильтром — тот же самый линейный скан по resident Vec, что
    /// и в остальном поиске (search.rs уже объясняет, почему это ок).
    FileMeta {
        file_id: FileId,
        reply: oneshot::Sender<Option<(u64, Option<String>, String)>>,
    },
    ReadAt {
        file_id: FileId,
        offset: u64,
        len: u32,
        reply: Reply<Vec<u8>>,
    },
    Delete {
        file_id: FileId,
        reply: Reply<()>,
    },
    Restore {
        file_id: FileId,
        reply: Reply<()>,
    },
    Rename {
        file_id: FileId,
        new_name: String,
        reply: Reply<()>,
    },
    Move {
        file_id: FileId,
        new_parent: FileId,
        reply: Reply<()>,
    },
    SetFavorite {
        file_id: FileId,
        favorite: bool,
        reply: Reply<()>,
    },
    Shutdown {
        reply: oneshot::Sender<()>,
    },
}

/// Запускает актор в выделенном ОС-потоке (не в пуле tokio — Container не
/// должен делить поток с другими задачами) и возвращает канал команд.
pub fn spawn(container: Container) -> std::sync::mpsc::Sender<Command> {
    let (tx, rx) = std::sync::mpsc::channel::<Command>();
    std::thread::Builder::new()
        .name("cove-session-actor".into())
        .spawn(move || run(container, rx))
        .expect("не удалось запустить поток session-актора");
    tx
}

fn run(mut container: Container, rx: std::sync::mpsc::Receiver<Command>) {
    while let Ok(cmd) = rx.recv() {
        match cmd {
            Command::ListDir { folder_id, reply } => {
                let res = container
                    .list_dir(folder_id)
                    .map(|v| v.iter().map(FileEntryDto::from).collect());
                let _ = reply.send(res);
            }
            Command::ListTrash { reply } => {
                let entries = container.list_trash();
                let dtos = entries.iter().map(FileEntryDto::from).collect();
                let _ = reply.send(dtos);
            }
            Command::Search { query, reply } => {
                let res = container
                    .search(query)
                    .map(|v| v.iter().map(FileEntryDto::from).collect());
                let _ = reply.send(res);
            }
            Command::CreateFolder {
                name,
                parent_id,
                reply,
            } => {
                let res = container.create_folder(&name, parent_id);
                let _ = reply.send(res);
            }
            Command::Import {
                name,
                parent_id,
                data,
                reply,
            } => {
                let res = container.import_file_from_bytes(&name, parent_id, &data);
                let _ = reply.send(res);
            }
            Command::FileMeta { file_id, reply } => {
                let found = container
                    .search(SearchQuery::default())
                    .unwrap_or_default()
                    .into_iter()
                    .find(|e| e.file_id == file_id)
                    .map(|e| (e.size, e.mime_hint, e.name));
                let _ = reply.send(found);
            }
            Command::ReadAt {
                file_id,
                offset,
                len,
                reply,
            } => {
                let res = container.read_at(file_id, offset, len);
                let _ = reply.send(res);
            }
            Command::Delete { file_id, reply } => {
                let res = container.delete_file(file_id);
                let _ = reply.send(res);
            }
            Command::Restore { file_id, reply } => {
                let res = container.restore_file(file_id);
                let _ = reply.send(res);
            }
            Command::Rename {
                file_id,
                new_name,
                reply,
            } => {
                let res = container.rename_file(file_id, &new_name);
                let _ = reply.send(res);
            }
            Command::Move {
                file_id,
                new_parent,
                reply,
            } => {
                let res = container.move_file(file_id, new_parent);
                let _ = reply.send(res);
            }
            Command::SetFavorite {
                file_id,
                favorite,
                reply,
            } => {
                let res = container.set_favorite(file_id, favorite);
                let _ = reply.send(res);
            }
            Command::Shutdown { reply } => {
                let _ = container.close();
                let _ = reply.send(());
                return;
            }
        }
    }
    // Канал закрыт (все Sender-ы отброшены, например при вылете процесса
    // без явного logout) — доигрываем аккуратным close(), а не просто drop,
    // чтобы данные точно были закоммичены.
    let _ = container.close();
}
