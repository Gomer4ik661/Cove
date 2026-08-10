// Каркас Фазы 1 (ROADMAP.md). Модули существуют и типизированы по
// docs/ARCHITECTURE.md и docs/FORMAT.md, но большая часть логики — `todo!()`,
// это ещё не реализация Фаз 2+. allow(dead_code) снимется по мере того как
// эти модули начнут вызывать друг друга.
#![allow(dead_code)]

pub mod container;
pub mod crypto;
pub mod error;
pub mod fileops;
pub mod format;
pub mod search;
pub mod thumbnail;
pub mod users;

pub use container::{Container, FileId, LockedContainer, RecoveryPhrase};
pub use error::{CoveError, Result};
