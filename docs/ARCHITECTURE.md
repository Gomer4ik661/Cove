# Архитектура — Cove

Как Core-крейт раскладывается на модули, что видно на публичной границе
API, и как эта граница пересекается тремя разными GUI (Python/Kotlin/Web).
Синхронизировано с [FORMAT.md](FORMAT.md) (что лежит внутри контейнера) и
[THREAT_MODEL.md](THREAT_MODEL.md) (§3 — границы доверия между компонентами).

## 1. Workspace: кто от кого зависит

```
cove/
  core/                    # чистый Rust, НИКАКИХ pyo3/uniffi/axum в зависимостях
    src/
      lib.rs                 # публичный фасад — Container, LockedContainer, ...
      error.rs                # CoveError — единый тип ошибок
      crypto/
        kdf.rs                 # Argon2id
        aead.rs                 # XChaCha20-Poly1305
        keys.rs                 # HKDF-подключи, zeroize-обёртки
      format/
        header.rs, keyslots.rs, commit.rs, superblock.rs,
        file_table.rs, search_index.rs, data_blocks.rs, free_map.rs
      container/
        mod.rs                  # оркестрация: открытие, unlock, commit
        session.rs               # состояние разблокированной сессии (DEK в памяти)
      users.rs, fileops.rs, search.rs, thumbnail.rs

  bindings/
    python/                  # PyO3-крейт, зависит только от core
    android/                 # UniFFI-крейт, зависит только от core

  desktop/                  # Python + PySide6, зависит от bindings/python
  android-app/               # Kotlin + Compose, зависит от сгенерированных UniFFI-биндингов
  web/
    backend/                  # Axum, зависит от core НАПРЯМУЮ (Rust-to-Rust, без FFI)
    frontend/                  # Svelte/TS, говорит с backend только по HTTP
```

Правило, проверяемое в CI: `core/Cargo.toml` не должен содержать `pyo3`,
`uniffi`, `axum` ни в каком виде. Если Core тянет за собой биндинг-специфичные
зависимости — архитектура сломана, это должно валить сборку.

Direction of dependency: `GUI → bindings → core` (Python/Android) либо
`GUI → backend → core` (Web). Ни один GUI-слой не работает с форматом `.slr`
напрямую — единственный парсер формата живёт в `core`.

## 2. Публичный фасад Core

Небольшой набор типов, пересекающих границу FFI — только простые данные
(строки, байты, числа, Vec, enum), без generics и без времён жизни, которые
нельзя выразить в Python/Kotlin.

```rust
// Контейнер до ввода пароля — доступны только метаданные keyslot'ов
impl LockedContainer {
    fn open(path: &str) -> Result<LockedContainer, CoveError>;
    fn list_usernames(&self) -> Vec<String>;
    fn unlock(&self, username: &str, password: &str) -> Result<Container, CoveError>;
    fn unlock_with_recovery(&self, phrase: &str) -> Result<Container, CoveError>;
}

// Разблокированная сессия
impl Container {
    fn create(path: &str, admin_username: &str, admin_password: &str)
        -> Result<(Container, RecoveryPhrase), CoveError>;

    // пользователи
    fn add_user(&mut self, username: &str, password: &str, role: Role) -> Result<(), CoveError>;
    fn remove_user(&mut self, username: &str) -> Result<(), CoveError>;
    fn change_password(&mut self, username: &str, old: &str, new: &str) -> Result<(), CoveError>;

    // файлы
    fn list_dir(&self, folder_id: FileId) -> Result<Vec<FileEntry>, CoveError>;
    fn import_file(&mut self, src_path: &str, parent_id: FileId) -> Result<FileId, CoveError>;
    fn export_file(&self, file_id: FileId, dest_path: &str) -> Result<(), CoveError>;
    fn delete_file(&mut self, file_id: FileId) -> Result<(), CoveError>;
    fn rename_file(&mut self, file_id: FileId, new_name: &str) -> Result<(), CoveError>;
    fn move_file(&mut self, file_id: FileId, new_parent: FileId) -> Result<(), CoveError>;

    // потоковое чтение (см. §4) — то, через что видео получает seek
    fn file_size(&self, file_id: FileId) -> Result<u64, CoveError>;
    fn read_at(&self, file_id: FileId, offset: u64, len: u32) -> Result<Vec<u8>, CoveError>;

    fn search(&self, query: SearchQuery) -> Result<Vec<FileEntry>, CoveError>;
    fn thumbnail(&mut self, file_id: FileId) -> Result<FileId, CoveError>;

    fn close(self) -> Result<(), CoveError>; // явный commit + zeroize ключей
}
```

`Role`, `FileEntry`, `SearchQuery`, `RecoveryPhrase` — простые структуры/enum,
однозначно представимые и в PyO3, и в UniFFI без ручной адаптации.

## 3. Ошибки на границе FFI

Единый `CoveError` (через `thiserror`) с закрытым набором категорий:

| Категория | Пример | Важное правило |
|---|---|---|
| `AuthFailed` | неверный пароль | **Одна и та же ошибка** для "неверный пароль" и "нет такого юзера" — не давать enumerate пользователей по разнице в ответе |
| `FormatError` | битая структура при чтении | не включает сырые оффсеты/байты в текст, который может попасть в UI |
| `Io` | диск/права | |
| `NotFound` / `AlreadyExists` | файл/пользователь | |
| `PermissionDenied` | read-only пытается писать | завязано на `Role` из THREAT_MODEL §2.6 |

Маппинг на каждой границе:
- **PyO3**: `From<CoveError> for PyErr`, отдельные Python-исключения по
  категориям (`CoveAuthError`, `CoveFormatError`, ...) — desktop-приложение
  ловит их по типу, а не парсит строку
- **UniFFI**: тот же enum описан в UDL, генерирует Kotlin sealed class
- **Web (Axum)**: категория → HTTP-код (`AuthFailed`→401, `PermissionDenied`→403,
  `NotFound`→404, остальное→500). В тело ответа уходит **только категория**,
  никаких внутренних деталей — это прямое следствие THREAT_MODEL §3
  ("Web backend — наименее доверенный процесс"): то, что нельзя писать в
  логи по THREAT_MODEL, нельзя и отдавать наружу в HTTP-ответе

## 4. Конкурентность и стриминг

**Core API синхронный.** Внутри `container::mod` мутабельное состояние
контейнера защищено `RwLock`: много параллельных читателей (`read_at`,
`list_dir`, `search`), но коммит новой версии Superblock (FORMAT.md §6a)
сериализован — один писатель за раз, что и требует append-only/copy-on-write
схема по конструкции.

Каждый биндинг адаптирует это под свою модель конкурентности сам, Core в
эту сторону ничего не знает:
- **PyO3**: блокирующие вызовы освобождают GIL (`Python::allow_threads`)
- **Axum/Web**: `Container` живёт в отдельной задаче-акторе, HTTP-хендлеры
  общаются с ней через `mpsc`-канал — это, а не общий `Mutex` из async-кода,
  штатный паттерн для shared mutable ресурса в Tokio
- **UniFFI/Kotlin**: вызовы Core идут из корутины на `Dispatchers.IO`

Стриминг видео/аудио не тянет `Read + Seek` через границу FFI (это не
представимо в Python/Kotlin напрямую) — вместо этого каждая платформа
оборачивает `file_size` + `read_at` в свой нативный интерфейс:
Desktop — `QIODevice`, Android — кастомный `DataSource` для ExoPlayer,
Web — HTTP `Range`-запросы поверх тех же двух методов.

## 5. Версионирование

Core и оба bindings-крейта версионируются и релизятся вместе, из одного
workspace, одной версией — отдельной матрицы совместимости "Core vN работает
с bindings vM" в v1 нет и не нужно. Это не то же самое, что
`format_version` контейнера (FORMAT.md §7) — версия крейта про API, версия
формата про байты на диске; они меняются независимо.
