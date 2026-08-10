//! Типы, отражающие байтовую раскладку `.slr` из docs/FORMAT.md.
//! Parse/serialize реализуются в Фазе 2 (ROADMAP.md) — сейчас только структуры.

pub mod commit;
pub mod data_blocks;
pub mod file_table;
pub mod free_map;
pub mod header;
pub mod keyslots;
pub mod login_log;
pub mod search_index;
pub mod superblock;
pub(crate) mod wire;
